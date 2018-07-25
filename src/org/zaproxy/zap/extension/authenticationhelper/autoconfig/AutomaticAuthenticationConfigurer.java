package org.zaproxy.zap.extension.authenticationhelper.autoconfig;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Vector;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType;
import org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationMethod;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

import net.htmlparser.jericho.Source;

public class AutomaticAuthenticationConfigurer extends PluginPassiveScanner {

	private static final Logger logger = Logger.getLogger(AutomaticAuthenticationConfigurer.class);

	private PassiveScanThread parent = null;

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {

	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

		if (authenticationMethodAlreadyConfigured(msg)) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication is already configured, skipping remaining tasks. URI:"
						+ msg.getRequestHeader().getURI());
			}
			return; // TODO: user may want to setup another user(credentials) by simply logging in
					// as a different one
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Authentication is not already configured. Checking if we have any clue to configure one. URI:"
					+ msg.getRequestHeader().getURI());
		}

		AuthenticationMethodType neededAuthenticationMethodType = findNeededAuthenticationMethodType(msg);

		if (neededAuthenticationMethodType == null) {
			if (logger.isDebugEnabled()) {
				logger.debug("No clue to setup automatic configruation, skipping remaining tasks. URI:"
						+ msg.getRequestHeader().getURI());
			}
			return;
		} else if (neededAuthenticationMethodType instanceof HttpAuthenticationMethodType) {
			if (logger.isDebugEnabled()) {
				logger.debug("Attempting to auto configure HttpAuthenticationMethodType for "
						+ msg.getRequestHeader().getURI());
			}
			
			if(contextNotDefined(msg)) {
				Session session = Model.getSingleton().getSession();
				Context newContext = session.getNewContext(msg.getRequestHeader().getURI().toString());
				HttpAuthenticationMethodType authMethod = new HttpAuthenticationMethodType();
			}
			neededAuthenticationMethodType = (HttpAuthenticationMethodType) neededAuthenticationMethodType;
			List<Context> contexts = getConfiguredContexts(msg);
			try {

				// TODO: move credentials setup to scanHttpRequestSend method
				Class<?> authenticationCredentials = Class
						.forName("org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials");

				Field usernameField = authenticationCredentials.getField("username");
				usernameField.setAccessible(true);

				Field passwordField = authenticationCredentials.getField("password");
				passwordField.setAccessible(true);

				AuthenticationCredentials credentials = neededAuthenticationMethodType
						.createAuthenticationCredentials();

				usernameField.set(credentials, "user");
				passwordField.set(credentials, "secret123");

				AuthenticationMethod httpAuthenticationMethod;
				for (Context context : contexts) {
					if (!(context.getAuthenticationMethod().getType() instanceof HttpAuthenticationMethodType)) {
						Object obj = neededAuthenticationMethodType.createAuthenticationMethod(context.getIndex());
						Class<?> httpAuthenticationMethodClass = obj.getClass();
						logger.debug("Found class: " + httpAuthenticationMethodClass.getCanonicalName());
						// Class<?> httpAuthenticationMethodClass = Class.forName(
						// "org.zaproxy.zap.authentication.HttpAuthenticationMethodType.HttpAuthenticationMethod");

						Field hostNameField = httpAuthenticationMethodClass.getField("hostname");
						hostNameField.setAccessible(true);

						Field portField = httpAuthenticationMethodClass.getField("port");
						portField.setAccessible(true);

						Field realmField = httpAuthenticationMethodClass.getField("realm");
						realmField.setAccessible(true);

						logger.debug("creating new user");
						User newUser = new User(context.getIndex(), "user");
						newUser.setAuthenticationCredentials(credentials);
						// httpAuthenticationMethod = cls.newInstance();
						httpAuthenticationMethod = neededAuthenticationMethodType
								.createAuthenticationMethod(context.getIndex());

						hostNameField.set(httpAuthenticationMethod, msg.getRequestHeader().getURI().getHost());
						portField.set(httpAuthenticationMethod, msg.getRequestHeader().getURI().getPort());
						realmField.set(httpAuthenticationMethod, "test-login.com");

						context.setAuthenticationMethod(httpAuthenticationMethod);
					}
				}

				Model.getSingleton().getSession().saveAllContexts();
			} catch (ClassNotFoundException e) {
				logger.debug("Unable to get the class HttpAuthenticationMethod using reflection", e);
			} catch (NoSuchFieldException e) {
				logger.debug("Unable to get the fields of HttpAuthenticationMethod using reflection", e);
			} catch (SecurityException e) {
				logger.debug("Do not have enough permission to use reflection", e);
				// } catch (InstantiationException e) {
				// logger.debug("Unable to instantiate HttpAuthenticationMethod using
				// newInstance method", e);
			} catch (IllegalAccessException e) {
				logger.debug(
						"Do not have access to HttpAuthenticationMethod class to create one using newInstance method",
						e);
			} catch (URIException e) {
				if (logger.isDebugEnabled()) {
					logger.debug("Unable to parse URI " + msg.getRequestHeader().getURI(), e);
				}
			}

			setupHttpAuthentication(msg);
			return;
		}

	}

	private AuthenticationMethodType findNeededAuthenticationMethodType(HttpMessage msg) {
		if (msg.getResponseHeader().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
			// List<Context> contexts = getConfiguredContexts(msg);
			// for (Context context : contexts) {
			// if (context.getAuthenticationMethod().getType() instanceof
			// ManualAuthenticationMethodType) {
			// return new HttpAuthenticationMethodType();
			// }
			// }
			return new HttpAuthenticationMethodType();
		}
		// TODO: add logic to detect form based authentication
		return null;
	}

	private boolean authenticationMethodAlreadyConfigured(HttpMessage msg) {
		if (contextNotDefined(msg)) {
			return false;
		}

		if (noAuthenticationMethodConfigured(msg)) {
			return false;
		}
		return false;
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

			// TODO: we may end up in loop
			if (!configuredAuthenticationMethod.isConfigured()) {
				if (logger.isDebugEnabled()) {
					logger.debug("AuthenticationMethod is not correctly configured for context: " + context.getName());
				}
				return true;
			}
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Authentication method is already configured for URI: " + msg.getRequestHeader().getURI());
		}
		return false;
	}

	private boolean contextNotDefined(HttpMessage msg) {
		List<Context> contexts = getConfiguredContexts(msg);

		if (contexts == null || contexts.isEmpty()) {
			return true;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Contexts are already defined for the URI: " + msg.getRequestHeader().getURI());
		}
		return false;
	}

	private List<Context> getConfiguredContexts(HttpMessage msg) {
		// TODO: what if the URI is excluded from the context
		return Model.getSingleton().getSession().getContextsForUrl(msg.getRequestHeader().getURI().toString());
	}

	private void setupHttpAuthentication(HttpMessage msg) {
		Vector<String> wwwAuthHeaders = msg.getResponseHeader().getHeaders(HttpHeader.WWW_AUTHENTICATE);
		if (wwwAuthHeaders != null) {
			Session session = Model.getSingleton().getSession();
			List<Context> contexts = session.getContextsForUrl(msg.getRequestHeader().getURI().toString());
			if (contexts != null && !contexts.isEmpty()) {
				for (Context context : contexts) {
					if (context.getAuthenticationMethod() != null) {
						if (!context.getAuthenticationMethod().isConfigured()) {
							logger.debug("Authentication method not configured yet, trying to automatically configure");

							HttpAuthenticationMethodType authMethod = new HttpAuthenticationMethodType();
							authMethod.createAuthenticationMethod(context.getIndex());
						}
					}
					// context.setAuthenticationMethod(authenticationMethod);
				}
			} else {
				logger.debug("No context found for URI: " + msg.getRequestHeader().getURI() + " ");
				Context newContext = session.getNewContext(msg.getRequestHeader().getURI().toString());
				HttpAuthenticationMethodType authMethod = new HttpAuthenticationMethodType();
				authMethod.createAuthenticationMethod(newContext.getIndex());
			}
		}
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public void setEnabled(boolean enabled) {
		// does not apply
	}

	@Override
	public AlertThreshold getAlertThreshold() {
		return AlertThreshold.LOW;
	}

	@Override
	public void setAlertThreshold(AlertThreshold alertThreshold) {
		// does not apply
	}

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public boolean appliesToHistoryType(int historyType) {
		return true;
	}

	@Override
	public String getName() {
		return "AuthenticationMethodScanner";
	}

	@Override
	public int getPluginId() {
		return 50002;
	}

}
