package org.zaproxy.zap.extension.authenticationhelper.autoconfig;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.authenticationhelper.autoconfig.AutomaticAuthenticationConfigurer.AuthenticationScheme;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/**
 * This {@code Object} is mainly used to store and retrieve the parameters that
 * are detected by {@link AutomaticAuthenticationConfigurer} passive scan rule.
 * It is also possible to set data manually so that it is possible to set
 * credentials in headless mode. This will be then put into a
 * {@code FileConfiguration} so that we can access it in headless mode.
 * 
 * @since 1.1.0
 */
public class AuthenticationAutoConfigurationParam implements Serializable {

	private static final long serialVersionUID = 4665321751529987567L;
	
	private static final Logger logger = Logger.getLogger(AuthenticationAutoConfigurationParam.class);

	/**
	 * The domain for which other params in this {@code Object} are applicable. This
	 * cannot be {@code null}. This is kind of a {@code key} for this
	 * {@code Object}. With the knowledge of {@code domain} value, this
	 * {@code Object} can be retrieved from {@code FileConfiguration} from which
	 * other params can be accessed or set.
	 * <p>
	 * This was chosen as key mainly because in headless mode it is the only known
	 * value.
	 */
	private String domain;

	/**
	 * represents the authentication scheme being used
	 */
	private AuthenticationScheme scheme;

	/**
	 * The {@link HttpMessage} from which auto configuration is initiated
	 */
	private HttpMessage msg;

	/**
	 * The {@code List} of {@link Context} for which auto configuration is
	 * attempted.
	 */
	private List<Context> contexts;

	/**
	 * The {@link User}s of this {@link #domain}. {@code User}s are added to this
	 * list by {@code AutomaticAuthenticationConfigurer} and manually(in headless
	 * mode) by calling {@code #createUser(String, String)}
	 */
	private List<User> configuredUsers;

	private ExtensionUserManagement userExtension;

	public AuthenticationAutoConfigurationParam() {
	}

	public AuthenticationAutoConfigurationParam(String domain, HttpMessage msg) {
		if (domain == null || domain.isEmpty()) {
			throw new IllegalArgumentException("the domain cannot be null or empty");
		}

		if (msg == null) {
			throw new IllegalArgumentException("the HttpMessage cannot be null or empty");
		}
		this.domain = domain;
		this.msg = msg;
	}

	/**
	 * Create and register a {@link User} {@link Context} by simply providing user
	 * name and password
	 * 
	 * @param username
	 *            cannot be null or empty
	 * @param password
	 *            cannot be null or empty
	 */
	public void setupUser(String username, String password) {
		if (username == null || password == null) {
			throw new IllegalArgumentException("username or password cannot be null");
		}

		if (username.isEmpty() || password.isEmpty()) {
			throw new IllegalArgumentException("username or password cannot be empty");
		}

		AuthenticationCredentials credentials = new UsernamePasswordAuthenticationCredentials(username, password);
		createAndRegisterUserToContexts(credentials);
	}

	/**
	 * Create and register a {@link User} to the {@link Context} by providing the
	 * {@link AuthenticationCredentials}
	 * 
	 * @param credentials
	 *            cannot be null
	 */
	public void setupUser(AuthenticationCredentials credentials) {
		if (credentials == null) {
			throw new IllegalArgumentException("The credentials cannot be null");
		}
		createAndRegisterUserToContexts(credentials);
	}

	public List<Context> getContexts() {
		return contexts;
	}

	public void setContexts(List<Context> contexts) {
		this.contexts = contexts;
	}

	public String getDomain() {
		return domain;
	}

	public AuthenticationScheme getScheme() {
		return scheme;
	}

	public void setScheme(AuthenticationScheme scheme) {
		this.scheme = scheme;
	}

	public List<User> getConfiguredUsers() {
		if (configuredUsers == null) {
			configuredUsers = new ArrayList<>();
		}
		return configuredUsers;
	}

	public void setConfiguredUsers(List<User> users) {
		configuredUsers = users;
	}

	private void createAndRegisterUserToContexts(AuthenticationCredentials credentials) {
		User newUser;
		String username = null;
		if(credentials instanceof UsernamePasswordAuthenticationCredentials) {
			username = ((UsernamePasswordAuthenticationCredentials) credentials).getUsername();
		} else {
			username = "user-" + getConfiguredUsers().size();
		}
		
		for (Context context : contexts) {
			newUser = new User(context.getIndex(), username);
			newUser.setAuthenticationCredentials(credentials);
			newUser.setEnabled(true);
			getUserExt().getContextUserAuthManager(context.getIndex()).addUser(newUser);
			logger.info("Registered new user, " + username + " to the context " + context.getName());
		}
	}

	private ExtensionUserManagement getUserExt() {
		if (userExtension == null) {
			userExtension = Control.getSingleton().getExtensionLoader().getExtension(ExtensionUserManagement.class);
		}
		return userExtension;
	}

	@Override
	public String toString() {
		return "AuthenticationAutoConfigurationParam [domain=" + domain + ", scheme=" + scheme + ", URI="
				+ msg.getRequestHeader().getURI() + ", contexts=" + contexts + ", configuredUsers=" + configuredUsers
				+ "]";
	}

}
