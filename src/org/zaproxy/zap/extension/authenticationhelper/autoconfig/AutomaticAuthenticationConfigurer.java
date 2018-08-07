package org.zaproxy.zap.extension.authenticationhelper.autoconfig;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.auth.AuthChallengeParser;
import org.apache.commons.httpclient.auth.MalformedChallengeException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType.HttpAuthenticationMethod;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationMethod;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.authenticationhelper.ExtensionAuthenticationHelper;
import org.zaproxy.zap.extension.authenticationhelper.OptionsParamAuthenticationHelper;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.StructuralSiteNode;
import org.zaproxy.zap.users.User;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.FormControlType;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

/**
 * The passive scan rule for automatic authentication configuration
 * 
 * @since 1.1.0
 */
public class AutomaticAuthenticationConfigurer implements PassiveScanner {

	//@formatter:off
	public enum AuthenticationScheme {
		HTTP_BASIC,
		HTTP_DIGEST,
		HTTP_NTLM,
		FORM,
		JSON;
		
		public static boolean isHttpScheme(AuthenticationScheme scheme) {
			return scheme.toString().startsWith("HTTP_");
		}
	}
	//@formatter:on

	private static final Logger logger = Logger.getLogger(AutomaticAuthenticationConfigurer.class);

	private PassiveScanThread parentPassiveScanThread = null;

	private ExtensionAuthenticationHelper authHelperExtension;

	public AutomaticAuthenticationConfigurer(ExtensionAuthenticationHelper authHelperExtension) {
		this.authHelperExtension = authHelperExtension;
	}

	/**
	 * If {@link #scanHttpResponseReceive(HttpMessage, int, Source)} has configured
	 * an {@code AuthenticationScheme.HTTP_BASIC} for the {@code domain} of the sent
	 * and received {@code HttpMessage}, then this will setup the
	 * {@link AuthenticationCredentials} for the configured
	 * {@link AuthenticationMethod}.
	 */
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		try {
			String domain = msg.getRequestHeader().getURI().getHost();
			AuthenticationAutoConfigurationParam autoConfiguredParam = getFileConfiguration()
					.getAutoConfiguredParam(domain);

			if (autoConfiguredParam == null) {
				// no authentication needed or when scanning the response the scanner did not
				// find any clue to setup appropriate authentication method
				return;
			}

			// grabbing the password from HttpMessage and automatically setting up user (only
			// supported for basic, post schemes)
			if (autoConfiguredParam.getScheme().equals(AuthenticationScheme.HTTP_BASIC)) {
				String authorizationHeader = msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION);
				
				if(authorizationHeader == null || authorizationHeader.isEmpty() || !authorizationHeader.startsWith("Basic")) {
					return;
				}
				
				if (!autoConfiguredParam.getConfiguredUsers().isEmpty()) {
					// user already configured, only setup if different user
					UsernamePasswordAuthenticationCredentials credentials = getUsernamePasswordCredentials(
							authorizationHeader);
					if (credentials == null) {
						return;
					}

					UsernamePasswordAuthenticationCredentials oldCredentials;
					for (User user : autoConfiguredParam.getConfiguredUsers()) {
						oldCredentials = (UsernamePasswordAuthenticationCredentials) user
								.getAuthenticationCredentials();
						if (oldCredentials.getUsername().equals(credentials.getUsername())) {
							// user already configure with this credentials, skipping
							return;
						}
					}

					// new credentials captured
					autoConfiguredParam.setupUser(credentials);
					return;
				}

				UsernamePasswordAuthenticationCredentials credentials = getUsernamePasswordCredentials(
						authorizationHeader);
				if (credentials == null) {
					return;
				}

				autoConfiguredParam.setupUser(credentials);

				View.getSingleton().getOutputPanel()
						.append("Auto config: configured new user for " + msg.getRequestHeader().getURI() + "\n");
			}
		} catch (URIException e) {
			logger.error("Unable to get host name from URI " + msg.getRequestHeader().getURI(), e);
			return;
		}
	}

	/**
	 * Extracts the {@code username} and {@code password} from the
	 * {@code Authorization} header for {@code HTTP Basic} authentication scheme and
	 * returns {@code UsernamePasswordAuthenticationCredentials}
	 * 
	 * @param authorizationHeader
	 */
	private UsernamePasswordAuthenticationCredentials getUsernamePasswordCredentials(String authorizationHeader) {
		if (authorizationHeader == null || authorizationHeader.isEmpty() || !authorizationHeader.startsWith("Basic")) {
			throw new IllegalArgumentException("invalid authorization header");
		}
		String base64Credentials = authorizationHeader.substring("Basic".length()).trim();
		String decodedCredentials = new String(Base64.getDecoder().decode(base64Credentials), Charset.forName("UTF-8"));
		// decodedCredentials = username:password
		final String[] values = decodedCredentials.split(":", 2);
		if (values[0] == null || values[0].isEmpty()) {
			throw new IllegalArgumentException("invalid authorization header");
		}
		if (values[1] == null || values[1].isEmpty()) {
			throw new IllegalArgumentException("invalid authorization header");
		}
		return new UsernamePasswordAuthenticationCredentials(values[0], values[1]);
	}

	/**
	 * Scans the response and automatically configures appropriate
	 * {@link AuthenticationMethod} if possible.
	 * <p>
	 * {@link #scanHttpRequestSend(HttpMessage, int)} takes care of configuring the
	 * {@code AuthenticationCredentials}
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

		if (authenticationMethodAlreadyConfigured(msg)) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method is already configured, skipping remaining tasks. URI:"
						+ msg.getRequestHeader().getURI());
			}
			return;
		}

		// ------ authentication method not configured yet ------
		if (logger.isDebugEnabled()) {
			logger.debug(
					"Authentication method is not yet configured, scanning to configure one if possible, URI: "
							+ msg.getRequestHeader().getURI());
		}

		AuthenticationScheme neededAuthenticationScheme = findNeededAuthenticationScheme(msg, source);

		if (neededAuthenticationScheme == null) {
			// unsupported scheme or no authentication needed
			return;
		}

		// ----- got some clue to auto configure authentication method ------

		List<Context> contexts = getContexts(msg);

		if (contexts == null) {
			return; // error message already logged, no point in continuing
		}

		AuthenticationMethod authenticationMethod = setupAuthenticationMethod(neededAuthenticationScheme, msg,
				contexts);

		if (authenticationMethod == null) {
			return; // error message already logged, no point in continuing
		}

		for (Context context : contexts) {
			context.setAuthenticationMethod(authenticationMethod);
		}

		try {
			AuthenticationAutoConfigurationParam autoConfigParam = new AuthenticationAutoConfigurationParam(
					msg.getRequestHeader().getURI().getHost(), msg);
			autoConfigParam.setContexts(contexts);
			autoConfigParam.setScheme(neededAuthenticationScheme);
			getFileConfiguration().addAutoConfiguredParam(autoConfigParam);
		} catch (URIException e) {
			logger.error("Auto-configuration failed, unable to get host from URI " + msg.getRequestHeader().getURI(),
					e);
			return;
		}

		Model.getSingleton().getSession().saveAllContexts();
	}

	private AuthenticationMethod setupAuthenticationMethod(AuthenticationScheme neededAuthenticationScheme,
			HttpMessage msg, List<Context> contexts) {
		AuthenticationMethod authenticationMethod = null;
		StringBuilder sb;
		switch (neededAuthenticationScheme) {
		case HTTP_BASIC:
			// intentional fall through
		case HTTP_DIGEST:
			// intentional fall through
		case HTTP_NTLM:
			authenticationMethod = setupHttpAuthenticationMethod(neededAuthenticationScheme, msg, contexts);
			break;
		case FORM:
			// the context id is not used by the method, so passing dummy value
			authenticationMethod = new FormBasedAuthenticationMethodType().createAuthenticationMethod(-1);
			sb = new StringBuilder();
			sb.append("Auto config: form based authentication method set for ");
			sb.append( msg.getRequestHeader().getURI());
			sb.append("\n");
			sb.append("Auto config: please login to complete the configuration");
			View.getSingleton().getOutputPanel().append(sb.toString());
			break;
		case JSON:
			// the context id is not used by the method, so passing dummy value
			authenticationMethod = new JsonBasedAuthenticationMethodType().createAuthenticationMethod(-1);
			sb = new StringBuilder();
			sb.append("Auto config: json based authentication method set for ");
			sb.append( msg.getRequestHeader().getURI());
			sb.append("\n");
			sb.append("Auto config: please login to complete the configuration");
			View.getSingleton().getOutputPanel().append(sb.toString());
			break;
		}
		return authenticationMethod;
	}

	@SuppressWarnings("unchecked")
	private AuthenticationMethod setupHttpAuthenticationMethod(AuthenticationScheme scheme, HttpMessage msg,
			List<Context> contexts) {
		if (!AuthenticationScheme.isHttpScheme(scheme)) {
			throw new IllegalArgumentException("only HTTP based authentication scheme is expected, found " + scheme);
		}
		logger.info("Attempting to auto configure HTTP authentication scheme for " + msg.getRequestHeader().getURI());
		// TODO support auto configuration when multiple schemes are specified
		String wwwAuthenticateValue = msg.getResponseHeader().getHeader(HttpHeader.WWW_AUTHENTICATE);
		if (wwwAuthenticateValue == null || wwwAuthenticateValue.isEmpty()) {
			throw new IllegalArgumentException("no WWW-Authenticate header found");
		}
		Map<String, String> params = null;
		try {
			params = AuthChallengeParser.extractParams(wwwAuthenticateValue);
		} catch (MalformedChallengeException e) {
			logger.error("Auto-configuration failed, unable to extract the authentication challenges from response", e);
			return null;
		}

		HttpAuthenticationMethod authenticationMethod = new HttpAuthenticationMethod();
		authenticationMethod.setLoggedOutIndicatorPattern(HttpHeader.WWW_AUTHENTICATE);

		String hostName;
		try {
			hostName = msg.getRequestHeader().getURI().getHost();
		} catch (URIException e) {
			logger.error(
					"Auto-configuration failed, unable to get host name from URI " + msg.getRequestHeader().getURI(),
					e);
			return null;
		}
		authenticationMethod.setHostname(hostName);
		authenticationMethod.setPort(msg.getRequestHeader().getURI().getPort());
		authenticationMethod.setRealm(params.get("realm"));

		StringBuilder outputMsg = new StringBuilder();
		outputMsg.append("Auto config: configured HTTP authentication method for ");
		outputMsg.append(msg.getRequestHeader().getURI());
		outputMsg.append("\n");

		if (scheme.equals(AuthenticationScheme.HTTP_BASIC)) {
			outputMsg.append(
					"Auto config: login to the web application to automatically setup a user or go to `Session Properties` to manually setup a user\n");
		} else {
			outputMsg.append("Auto config: go to `Session Properties` to manually setup a user\n");
		}
		View.getSingleton().getOutputPanel().append(outputMsg.toString());

		return authenticationMethod;
	}

	/**
	 * Returns a {@code List} of {@link Context} that the input {@code HttpMessage}
	 * belongs to. If no {@code Context} is defined yet, then a new {@code Context}
	 * is created and added to the {@link Session}.
	 * <p>
	 * If the {@code URI} of the input {@code HttpMessage} is
	 * {@code http://192.168.56.101/bodgeit/login.jsp} then
	 * {@code http://192.168.56.101/bodgeit.*} is included to the new
	 * {@code Context}.
	 * 
	 * @param msg the {@code HttpMessage}
	 */
	private List<Context> getContexts(HttpMessage msg) {
		List<Context> contexts = getConfiguredContexts(msg);
		if (contexts == null) {
			contexts = new ArrayList<>();
		}

		if (contexts.isEmpty()) {
			Session session = Model.getSingleton().getSession();
			StructuralSiteNode ssn = new StructuralSiteNode(msg.getHistoryRef().getSiteNode().getParent());
			Context newContext = session.getNewContext(ssn.getName());
			try {
				newContext.addIncludeInContextRegex(ssn.getRegexPattern());
				logger.info("Created new context, " + newContext.getName());
			} catch (DatabaseException e) {
				logger.error("Auto-configuration fialed, unable to create a context for URI "
						+ msg.getRequestHeader().getURI(), e);
				return null;
			}
			Model.getSingleton().getSession().saveContext(newContext);
			contexts.add(newContext);
			View.getSingleton().getOutputPanel()
					.append("Auto config: new context created " + newContext.getName() + "\n");
		}
		return contexts;
	}

	private AuthenticationScheme findNeededAuthenticationScheme(HttpMessage msg, Source source) {
		if (isHttpScheme(msg)) {
			return resolveHttpScheme(msg.getResponseHeader().getHeader(HttpHeader.WWW_AUTHENTICATE));
		}

		AuthenticationScheme postBasedScheme = checkAndGetPostBasedScheme(source);
		if (postBasedScheme != null) {
			return postBasedScheme;
		}
		return null;
	}

	private AuthenticationScheme checkAndGetPostBasedScheme(Source source) {
		int passwordFieldCount;
		List<Element> forms = source.getAllElements(HTMLElementName.FORM);
		for (Element form : forms) {
			passwordFieldCount = 0;
			for (Element inputElement : form.getAllElements(HTMLElementName.INPUT)) {
				if (inputElement.getFormControl().getFormControlType().equals(FormControlType.PASSWORD)) {
					passwordFieldCount++;
				}
			}
			if (passwordFieldCount == 1) {
				String encoding = form.getAttributeValue("enctype");
				if (encoding != null && !encoding.isEmpty() && encoding.equalsIgnoreCase("application/json")) {
					return AuthenticationScheme.JSON;
				}
				return AuthenticationScheme.FORM;
			}
		}
		return null;
	}

	private boolean isHttpScheme(HttpMessage msg) {
		boolean isHttpAuth = msg.getResponseHeader().getStatusCode() == HttpStatus.SC_UNAUTHORIZED
				|| msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION) != null;
		return isHttpAuth;
	}

	private AuthenticationScheme resolveHttpScheme(String wwwAuthenticateHeader) {
		String[] params = wwwAuthenticateHeader.split(" ");
		if (params[0].equalsIgnoreCase("basic")) {
			return AuthenticationScheme.HTTP_BASIC;
		} else if (params[0].equalsIgnoreCase("digest")) {
			return AuthenticationScheme.HTTP_DIGEST;
		} else if (params[0].equalsIgnoreCase("ntlm")) {
			return AuthenticationScheme.HTTP_NTLM;
		}
		logger.warn("unsupported scheme found in WWW-Authenticate header " + wwwAuthenticateHeader);
		return null;
	}

	private boolean authenticationMethodAlreadyConfigured(HttpMessage msg) {
		if (contextNotDefined(msg)) {
			return false;
		}

		if (noAuthenticationMethodConfigured(msg)) {
			return false;
		}
		return true;
	}

	private boolean noAuthenticationMethodConfigured(HttpMessage msg) {
		List<Context> contexts = getConfiguredContexts(msg);
		AuthenticationMethod configuredAuthenticationMethod;
		for (Context context : contexts) {
			configuredAuthenticationMethod = context.getAuthenticationMethod();
			if (configuredAuthenticationMethod instanceof ManualAuthenticationMethod) {
				if (logger.isDebugEnabled()) {
					logger.debug("ManualAuthenticationMethod is configured for context: " + context.getName());
				}
				return true;
			}

			if (!configuredAuthenticationMethod.isConfigured()) {
				if (logger.isDebugEnabled()) {
					logger.debug("AuthenticationMethod is not correctly configured for context: " + context.getName());
				}
				return true;
			}
		}
		return false;
	}

	private boolean contextNotDefined(HttpMessage msg) {
		List<Context> contexts = getConfiguredContexts(msg);

		if (contexts == null || contexts.isEmpty()) {
			return true;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Context(s) already defined for the URI: " + msg.getRequestHeader().getURI());
		}
		return false;
	}

	private List<Context> getConfiguredContexts(HttpMessage msg) {
		// TODO: what if the URI is excluded from the context
		return Model.getSingleton().getSession().getContextsForUrl(msg.getRequestHeader().getURI().toString());
	}

	@Override
	public boolean isEnabled() {
		// TODO get from variable instead
		return true;
	}

	@Override
	public void setEnabled(boolean enabled) {
		// TODO set to variable instead
	}

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parentPassiveScanThread = parent;
	}

	@Override
	public boolean appliesToHistoryType(int historyType) {
		return historyType == HistoryReference.TYPE_PROXIED;
	}

	@Override
	public String getName() {
		return "AuthenticationMethodScanner";
	}

	private OptionsParamAuthenticationHelper getFileConfiguration() {
		if (authHelperExtension != null) {
			return authHelperExtension.getOptionsParam();
		}
		return null;
	}
}
