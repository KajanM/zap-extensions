/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.authenticationhelper.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.util.regex.Pattern;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.Border;
import javax.swing.border.EtchedBorder;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationMethod;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.StructuralSiteNode;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ContextCreateDialog;
import org.zaproxy.zap.view.ContextIncludePanel;

//TODO: internationalization
public class AuthenticationConfigurationChecklistPanel extends JPanel {

	private static final long serialVersionUID = 8228766560419086082L;

	private static final Logger logger = Logger.getLogger(AuthenticationConfigurationChecklistPanel.class);

	/**
	 * Constant indicating the <strong>overall authentication configuration
	 * status</strong>. This can be one of {@code GOOD}, {@code BAD},
	 * {@code MINIMAL}, {@code VALIDATION_IN_PROCESS} and {@code NEED_RECHECK}.
	 * <p>
	 * This should be differentiated from {@link AuthenticationStatus} which
	 * indicates the <strong>authentication status</strong>.
	 * <p>
	 * {@code GOOD} - All conditions are met. This does <strong>not</strong>
	 * necessarily mean that authentication will be successful. Even with
	 * {@code GOOD} state, the authentication may fail. With this state the user can
	 * start authentication status scan by pressing the scan button in
	 * {@link AuthenticationHelperDialog}.
	 * <p>
	 * {@code BAD} - One or more condition is not satisfied. The authentication
	 * status scan cannot be started with this state.
	 * <P>
	 * {@code MINIMAL} - All conditions are met, but only one of logged in or logged
	 * out indicator is given. the user can start authentication status scan by
	 * pressing the scan button in {@link AuthenticationHelperDialog}.
	 * <p>
	 * {@code VALIDATION_IN_PROCESS} - This is an intermediate step and not visible
	 * to user. In the series of multiple checks, so far all conditions are met, but
	 * we are not done with all checks.
	 * <p>
	 * {@code NEED_RECHECK} - This state is set if the user has pressed any of the
	 * settings button in {@link AuthenticationConfigurationChecklistPanel}. The
	 * authentication status scan cannot be started with this state.
	 * <p>
	 * Following checks are made to determine the {@code ConfigurationStatus}.
	 * <ol>
	 * <li>Whether or not good starting point({@code URI}) is given</li>
	 * <li>Whether or not {@link Context} is defined for the provided starting
	 * point</li>
	 * <li>Whether or not {@link AuthenticationMethod} is configured for the
	 * selected context.</li>
	 * <li>Whether or not {@link User} is configured for the selected context.</li>
	 * <li>Whether or not logged in, out indicators are defined for the selected
	 * context</li>
	 * </ol>
	 *
	 */
	public enum ConfigurationStatus {
		//@formatter:off
		GOOD, 
		BAD, 
		MINIMAL, 
		VALIDATION_IN_PROCESS,
		NEED_RECHECK;
		//@formatter:on
	}

	/**
	 * This {@code Icon} will be set to following labels if matching configuration
	 * status is found to be good.
	 * <ol>
	 * <li>{@code labelContextStatus}</li>
	 * <li>{@code labelUserStatus}</li>
	 * <li>{@code labelAuthenticationMethodStatus}</li>
	 * <li>{@code labelLoggedInOutIndicatorStatus}</li>
	 * </ol>
	 * This is <strong>not</strong> the matching {@code Icon} for
	 * {@code ConfigurationStatus.GOOD} as the {@code ConfigurationStatus} indicates
	 * the overall configuration status and this {@code Icon} is for individual
	 * configuration status.
	 * <p>
	 * Eagerly loaded.
	 * 
	 * @see ConfigurationStatus
	 */
	private static final Icon GOOD_CONFIGURATION_ICON;

	/**
	 * This {@code Icon} will be set to following labels if matching configuration
	 * status is found to be bad.
	 * <ol>
	 * <li>{@code labelContextStatus}</li>
	 * <li>{@code labelUserStatus}</li>
	 * <li>{@code labelAuthenticationMethodStatus}</li>
	 * <li>{@code labelLoggedInOutIndicatorStatus}</li>
	 * </ol>
	 * This is the matching {@code Icon} for {@code ConfigurationStatus.BAD}.
	 * <p>
	 * Eagerly loaded.
	 * 
	 * @see ConfigurationStatus
	 */
	private static final Icon BAD_CONFIGURATION_ICON;

	/**
	 * This {@code Icon} will be set to following labels if the user has pressed any
	 * settings button in {@code AuthenticationConfigurationChecklistPanel}
	 * <ol>
	 * <li>{@code labelContextStatus}</li>
	 * <li>{@code labelUserStatus}</li>
	 * <li>{@code labelAuthenticationMethodStatus}</li>
	 * <li>{@code labelLoggedInOutIndicatorStatus}</li>
	 * </ol>
	 * This is the matching {@code Icon} for
	 * {@code ConfigurationStatus.NEED_RECHECK}.
	 * <p>
	 * Eagerly loaded.
	 * 
	 * @see ConfigurationStatus
	 */
	private static final Icon NOT_VALIDATED_YET_ICON;

	/**
	 * This {@code Icon} will be set to only {@code labelLoggedInOutIndicatorStatus}
	 * if only one of logged in/out indicator is provided.
	 * <p>
	 * This is the matching {@code Icon} for {@code ConfigurationStatus.MINIMAL}.
	 * <p>
	 * Eagerly loaded.
	 * 
	 * @see ConfigurationStatus
	 */
	private static final Icon MINIMAL_CONFIGURATION_ICON;

	/**
	 * The preferred width for the {@code JButton}s with gear icon in the
	 * {@code AuthenticationConfigurationChecklistPanel}
	 */
	private static final int PREFERED_WIDTH = 25;

	/**
	 * The preferred height for the {@code JButton}s with gear icon in the
	 * {@code AuthenticationConfigurationChecklistPanel}
	 */
	private static final int PREFERED_HEIGHT = 25;

	/**
	 * The parent container of {@link AuthenticationConfigurationChecklistPanel}.
	 */
	private final AuthenticationHelperDialog helperDialog;

	/**
	 * {@code JLabel} used to provide hint on user's next step.
	 * <p>
	 * Eg.
	 * <ul>
	 * 	<li>Click the Select button to provide a starting point</li>
	 * 	<li>Click the active gear icon to create a context</li>
	 * 	<li>Please refresh to re run the checks with updated settings</li>
	 * </ul>
	 */
	private final JLabel labelHintOnNextStep;
	
	/**
	 * {@code JLabel} with the constant text "Define a context" and varying tool tip text.
	 * The status is indicated by setting one of the following {@code Icon}.
	 * <ol>
	 * 	<li>{@link #GOOD_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #BAD_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #NOT_VALIDATED_YET_ICON}</li>
	 * </ol>
	 */
	private final JLabel labelContextStatus;
	
	/**
	 * {@code JLabel} with the constant text "Configure user for the selected context" and varying tool tip text.
	 * The status is indicated by setting one of the following {@code Icon}.
	 * <ol>
	 * 	<li>{@link #GOOD_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #BAD_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #NOT_VALIDATED_YET_ICON}</li>
	 * </ol>
	 */
	private final JLabel labelUserStatus;
	
	/**
	 * {@code JLabel} with the constant text "Configure authentication method for the selected context" and varying tool tip text.
	 * The status is indicated by setting one of the following {@code Icon}.
	 * <ol>
	 * 	<li>{@link #GOOD_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #BAD_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #NOT_VALIDATED_YET_ICON}</li>
	 * </ol>
	 */
	private final JLabel labelAuthenticationMethodStatus;
	
	/**
	 * {@code JLabel} with the constant text "Define logged in/out indicator for the selected context" and varying tool tip text.
	 * The status is indicated by setting one of the following {@code Icon}.
	 * <ol>
	 * 	<li>{@link #GOOD_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #BAD_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #MINIMAL_CONFIGURATION_ICON}</li>
	 * 	<li>{@link #NOT_VALIDATED_YET_ICON}</li>
	 * </ol>
	 */
	private final JLabel labelLoggedInOutIndicatorStatus;

	/**
	 * 
	 */
	private JButton btnContextProperties;
	private JButton btnAuthenticationProperties;
	private JButton btnUserProperties;
	private JButton btnIndicatorProperties;

	private ConfigurationStatus configurationStatus;

	static {
		GOOD_CONFIGURATION_ICON = new ImageIcon(AuthenticationConfigurationChecklistPanel.class
				.getResource("/org/zaproxy/zap/extension/authenticationhelper/resources/tick-circle.png"));
		NOT_VALIDATED_YET_ICON = new ImageIcon(AuthenticationConfigurationChecklistPanel.class
				.getResource("/org/zaproxy/zap/extension/authenticationhelper/resources/question-white.png"));
		BAD_CONFIGURATION_ICON = new ImageIcon(AuthenticationConfigurationChecklistPanel.class
				.getResource("/org/zaproxy/zap/extension/authenticationhelper/resources/cross-circle.png"));
		MINIMAL_CONFIGURATION_ICON = new ImageIcon(AuthenticationConfigurationChecklistPanel.class
				.getResource("/org/zaproxy/zap/extension/authenticationhelper/resources/exclamation-circle.png"));
	}

	public AuthenticationConfigurationChecklistPanel(AuthenticationHelperDialog helperDialog) {
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

		this.helperDialog = helperDialog;

		labelHintOnNextStep = new JLabel();
		labelContextStatus = new JLabel(
				Constant.messages.getString("authenticationhelper.checklist.label.context"),
				NOT_VALIDATED_YET_ICON, JLabel.LEFT);
		labelUserStatus = new JLabel(Constant.messages.getString("authenticationhelper.checklist.label.user"),
				NOT_VALIDATED_YET_ICON, JLabel.LEFT);
		labelAuthenticationMethodStatus = new JLabel(
				Constant.messages.getString("authenticationhelper.checklist.label.authentication"),
				NOT_VALIDATED_YET_ICON, JLabel.LEFT);
		labelLoggedInOutIndicatorStatus = new JLabel(
				Constant.messages.getString("authenticationhelper.checklist.label.loggedInOutIndicator"),
				NOT_VALIDATED_YET_ICON, JLabel.LEFT);

		JPanel hintOnNextStepPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		
		JPanel contextStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JPanel userStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JPanel authenticationMethodStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JPanel loggedInOutIndicatorStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

		Border emptyBorder = BorderFactory.createEmptyBorder(10, 10, 10, 10);
		Border matteBorder = BorderFactory.createMatteBorder(1, 17, 1, 1, Color.lightGray);
		hintOnNextStepPanel.setBorder(BorderFactory.createCompoundBorder(emptyBorder, matteBorder));
		hintOnNextStepPanel.add(labelHintOnNextStep);

		contextStatusPanel.add(getBtnContext());
		contextStatusPanel.add(labelContextStatus);

		authenticationMethodStatusPanel.add(getBtnAuthentication());
		authenticationMethodStatusPanel.add(labelAuthenticationMethodStatus);

		userStatusPanel.add(getBtnUser());
		userStatusPanel.add(labelUserStatus);

		loggedInOutIndicatorStatusPanel.add(getBtnIndicator());
		loggedInOutIndicatorStatusPanel.add(labelLoggedInOutIndicatorStatus);

		add(hintOnNextStepPanel);
		add(contextStatusPanel);
		add(authenticationMethodStatusPanel);
		add(userStatusPanel);
		add(loggedInOutIndicatorStatusPanel);

		Border outterBorder = BorderFactory.createEmptyBorder(10, 5, 5, 5);
		Border innerBorder = BorderFactory.createEtchedBorder(EtchedBorder.LOWERED);
		setBorder(BorderFactory.createCompoundBorder(outterBorder, innerBorder));
	}

	public void runCheck() {
		configurationStatus = ConfigurationStatus.VALIDATION_IN_PROCESS;

		if (noOrBadTarget()) {
			setBadTargetStatus();
			return; // no point in running remaining checks
		}
		setGoodTargetStatus();

		if (noContextSelected()) {
			setBadContextStatus();
			return; // no point in running remaining checks
		}
		setGoodContextStatus();

		checkAndUpdateAuthenticationMethodStatus();

		if (getConfiguredAuthenticationMethod() == null) {
			return;// no point in running remaining checks
		}

		checkAndUpdateUserStatus();

		checkAndUpdateIndicatorStatus();

		if (configurationStatus.equals(ConfigurationStatus.GOOD)) {
			configurationStatus = ConfigurationStatus.GOOD;
			setOverallGoodStatus();
			logger.debug("authentication configuration: good to go...");
		}
	}

	private void setGoodTargetStatus() {
		btnContextProperties.setEnabled(true);
	}

	private void checkAndUpdateUserStatus() {
		User selectedUser = getSelectedUser();
		if (selectedUser == null) {
			setBadUserStatus("No user selected");
			return;
		}

		if (!selectedUser.getAuthenticationCredentials().isConfigured()) {
			setBadUserStatus("User credentials not setup");
			return;
		}
		setGoodUserStatus();
	}

	@SuppressWarnings("incomplete-switch")
	private void checkAndUpdateIndicatorStatus() {
		Pattern inIndicator = getConfiguredAuthenticationMethod().getLoggedInIndicatorPattern();
		Pattern outIndicator = getConfiguredAuthenticationMethod().getLoggedOutIndicatorPattern();
		ConfigurationStatus indicatorStatus = checkIndicator(inIndicator, outIndicator);

		switch (indicatorStatus) {
		case MINIMAL:
			setMinimalIndicatorStatus();
			if (!configurationStatus.equals(ConfigurationStatus.BAD)) {
				setOverallMinimalStatus();
				// it's the last check in the series
				configurationStatus = ConfigurationStatus.MINIMAL;
			}
			break;
		case BAD:
			setBadIndicatorStatus("You must define at least one indicator");
			setOverallBadStatus("Click the gear icon to set logged in or logged out indicator");
			configurationStatus = ConfigurationStatus.BAD;
			break;
		case GOOD:
			setGoodIndicatorStatus();
			if (!configurationStatus.equals(ConfigurationStatus.BAD)) {
				// it's the last check in the series
				configurationStatus = ConfigurationStatus.GOOD;
			}
		}
	}

	private void checkAndUpdateAuthenticationMethodStatus() {
		AuthenticationMethod authenticationMethod = getConfiguredAuthenticationMethod();

		// it will not(?) hit, anyway let's check
		if (authenticationMethod == null) {
			setBadAuthenticationMethodStatus("Bad: No authentication method configured");
			setBadIndicatorStatus("Bad: Configure authentication method first");
			setOverallBadStatus("Click the gear icon to configure authentication method");
			configurationStatus = ConfigurationStatus.BAD;
			logger.debug("authentication configuration: bad - authentication method not defined");
			return; // no use in running remaining checks
		} else if (!authenticationMethod.isConfigured()) {
			setBadAuthenticationMethodStatus("Authentication method is not configured correclty");
			setOverallBadStatus("Bad: Authentication method is not configured correclty");
			configurationStatus = ConfigurationStatus.BAD;
			logger.debug("authentication configuration: bad - authenticaiton method is not configured properly");
		} else if (authenticationMethod instanceof ManualAuthenticationMethod) {
			setBadAuthenticationMethodStatus("Manual authenticaiton method found");
			setOverallBadStatus("Bad: Manual authenticaiton method found");
			configurationStatus = ConfigurationStatus.BAD;
			logger.debug("authentication configuration: bad - ManualAuthenticationMethod found");
		} else {
			setGoodAuthenticationMethodStatus();
			logger.debug("authentication configuration:in process - authentication method configured correctly");
		}
	}

	private void setOverallMinimalStatus() {
		labelHintOnNextStep.setText("Can proceed, it's good to define both indicators if possible");
		// labelOverallStatus.setIcon(MINIMAL_CONFIGURATION_ICON);
	}

	public ConfigurationStatus getConfigurationStatus() {
		return configurationStatus;
	}

	private void showContextPropertiesDialog(Context selectedContext) {
		View.getSingleton().showSessionDialog(Model.getSingleton().getSession(),
				ContextIncludePanel.getPanelName(selectedContext.getIndex()));
	}

	private Context getSelectedContext() {
		return helperDialog.getSelectedContext();
	}

	private void createContextAndShowContextPropertiesDialog(SiteNode startNode) {
		if (logger.isDebugEnabled()) {
			logger.debug("Automatically creating new context for the user for node " + startNode.getName());
		}
		Context newContext = Model.getSingleton().getSession().getNewContext(startNode.getName());
		try {
			newContext.addIncludeInContextRegex(new StructuralSiteNode(startNode).getRegexPattern());
			Model.getSingleton().getSession().saveContext(newContext);

			View.getSingleton().showSessionDialog(Model.getSingleton().getSession(),
					ContextIncludePanel.getPanelName(newContext.getIndex()));

		} catch (DatabaseException e) {
			// TODO: HELP: what should be the message passed to the user
			// if we are showing a warning dialog or something
		} catch (IllegalArgumentException e) {
			// TODO: thrown when creating a create a context with the deleted context's name
		}
	}

	private void showContextCreateDialog() {
		ContextCreateDialog contextCreateDialog = new ContextCreateDialog(View.getSingleton().getMainFrame());
		contextCreateDialog.setVisible(true);
	}

	public void setAppropriateToolTipAndActionListener() {
		Target node = helperDialog.getTarget();
		if (node == null) {
			btnContextProperties.setToolTipText("New context");
			btnContextProperties.addActionListener(e -> {
				settingsBtnPressed();
				logger.debug("target is null, calling ContextCreateDialog");
				showContextCreateDialog();
			});
			return;
		}

		removeExistingActionListeners();

		if (noContextSelected()) {
			if (node.getStartNode() == null) {
				btnContextProperties.setToolTipText("New context");
				logger.debug("start node is null, calling ContextCreateDialog");
				btnContextProperties.addActionListener(e -> {
					settingsBtnPressed();
					showContextCreateDialog();
				});
			} else {
				btnContextProperties.setToolTipText("New context with URI");
				if (logger.isDebugEnabled()) {
					logger.debug("Creating a new context for start node " + node.getStartNode().getName()
							+ " and showing the context properties dialog");
				}
				btnContextProperties.addActionListener(e -> {
					settingsBtnPressed();
					createContextAndShowContextPropertiesDialog(node.getStartNode());
				});
			}
		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("showing context properties dialog for context " + getSelectedContext());
			}
			btnContextProperties.setToolTipText("Context properties");
			btnContextProperties.addActionListener(e -> {
				settingsBtnPressed();
				showContextPropertiesDialog(getSelectedContext());
			});
		}
	}

	private void removeExistingActionListeners() {
		for (ActionListener listener : btnContextProperties.getActionListeners()) {
			btnContextProperties.removeActionListener(listener);
		}
	}

	private boolean noContextSelected() {
		return getSelectedContext() == null;
	}

	private void settingsBtnPressed() {
		setStatusToNotValidatedYet();
		labelHintOnNextStep.setText("Please refresh to re run the checks with updated settings");
	}

	private ConfigurationStatus checkIndicator(Pattern loggedInIndicatorPattern, Pattern loggedOutIndicatorPattern) {
		boolean inDefined = this.indicatorDefined(loggedInIndicatorPattern);
		boolean outDefined = this.indicatorDefined(loggedOutIndicatorPattern);
		if (inDefined && outDefined) {
			return ConfigurationStatus.GOOD;
		}

		if (inDefined || outDefined) {
			setMinimalIndicatorStatus();
			return ConfigurationStatus.MINIMAL;
		}

		return ConfigurationStatus.BAD;
	}

	private boolean indicatorDefined(Pattern indicator) {
		return indicator != null && !indicator.pattern().isEmpty();
	}

	private void setStatusToNotValidatedYet() {
		configurationStatus = ConfigurationStatus.NEED_RECHECK;

		labelContextStatus.setIcon(NOT_VALIDATED_YET_ICON);
		labelUserStatus.setIcon(NOT_VALIDATED_YET_ICON);
		labelAuthenticationMethodStatus.setIcon(NOT_VALIDATED_YET_ICON);
		labelLoggedInOutIndicatorStatus.setIcon(NOT_VALIDATED_YET_ICON);

		labelContextStatus.setToolTipText("press refresh to recheck");
		labelUserStatus.setToolTipText("press refresh to recheck");
		labelAuthenticationMethodStatus.setToolTipText("press refresh to recheck");
		labelLoggedInOutIndicatorStatus.setToolTipText("press refresh to recheck");
	}

	private void setBadTargetStatus() {
		setOverallBadStatus("Click the Select button to provide a starting point");

		configurationStatus = ConfigurationStatus.BAD;
		labelContextStatus.setIcon(BAD_CONFIGURATION_ICON);
		labelContextStatus.setToolTipText("Select a starting point first");

		btnContextProperties.setEnabled(false);
		btnAuthenticationProperties.setEnabled(false);
		btnIndicatorProperties.setEnabled(false);
		btnUserProperties.setEnabled(false);

		setBadAuthenticationMethodStatus("Select a starting point first");
		setBadIndicatorStatus("Select a starting point first");
		setBadUserStatus("Select a starting point first");
	}

	private void setBadContextStatus() {
		setOverallBadStatus("Click the active gear icon to create a context");

		configurationStatus = ConfigurationStatus.BAD;
		labelContextStatus.setIcon(BAD_CONFIGURATION_ICON);

		btnAuthenticationProperties.setEnabled(false);
		btnIndicatorProperties.setEnabled(false);
		btnUserProperties.setEnabled(false);

		setBadAuthenticationMethodStatus("No context defined");
		setBadIndicatorStatus("Define context first");
		setBadUserStatus("Define context first");
	}

	private void setGoodContextStatus() {
		labelContextStatus.setIcon(GOOD_CONFIGURATION_ICON);

		btnAuthenticationProperties.setEnabled(true);
		btnIndicatorProperties.setEnabled(true);
		btnUserProperties.setEnabled(true);
	}

	private void setBadAuthenticationMethodStatus(String toolTip) {
		labelAuthenticationMethodStatus.setIcon(BAD_CONFIGURATION_ICON);
		labelAuthenticationMethodStatus.setToolTipText(toolTip);
		btnUserProperties.setEnabled(false);
	}

	private void setGoodAuthenticationMethodStatus() {
		labelAuthenticationMethodStatus.setIcon(GOOD_CONFIGURATION_ICON);
		labelAuthenticationMethodStatus.setToolTipText("Authentication method is configured correctly");
		btnUserProperties.setEnabled(true);
	}

	private void setBadIndicatorStatus(String toolTip) {
		labelLoggedInOutIndicatorStatus.setIcon(BAD_CONFIGURATION_ICON);
		labelLoggedInOutIndicatorStatus.setToolTipText(toolTip);
	}

	private void setOverallBadStatus(String reason) {
		// we want to tell the user only the first reason for bad status
		if (!configurationStatus.equals(ConfigurationStatus.BAD)) {
			labelHintOnNextStep.setText(reason);
			// labelOverallStatus.setIcon(BAD_CONFIGURATION_ICON);
		}
	}

	private void setGoodIndicatorStatus() {
		labelLoggedInOutIndicatorStatus.setIcon(GOOD_CONFIGURATION_ICON);
		labelLoggedInOutIndicatorStatus.setToolTipText("Both logged in, out indicators are defined");
	}

	private void setOverallGoodStatus() {
		labelHintOnNextStep.setText("Good to go, press scan button to start scanning");
		// labelOverallStatus.setIcon(GOOD_CONFIGURATION_ICON);
	}

	private void setMinimalIndicatorStatus() {
		labelLoggedInOutIndicatorStatus.setIcon(MINIMAL_CONFIGURATION_ICON);
		labelLoggedInOutIndicatorStatus.setToolTipText("it's good to provide both logged indicators");
	}

	private void setBadUserStatus(String reason) {
		setOverallBadStatus(reason);

		configurationStatus = ConfigurationStatus.BAD;
		labelUserStatus.setIcon(BAD_CONFIGURATION_ICON);
		labelUserStatus.setToolTipText(reason);
	}

	private void setGoodUserStatus() {
		configurationStatus = ConfigurationStatus.VALIDATION_IN_PROCESS;
		labelUserStatus.setIcon(GOOD_CONFIGURATION_ICON);
		labelUserStatus.setToolTipText("User is configured correctly");
	}

	private JButton getBtnContext() {
		if (btnContextProperties == null) {
			btnContextProperties = new JButton();
			btnContextProperties
					.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(AuthenticationConfigurationChecklistPanel.class
							.getResource("/org/zaproxy/zap/extension/authenticationhelper/resources/gear.png"))));

			btnContextProperties.setPreferredSize(new Dimension(PREFERED_WIDTH, PREFERED_HEIGHT));
		}
		setAppropriateToolTipAndActionListener();
		return btnContextProperties;
	}

	private JButton getBtnAuthentication() {
		if (btnAuthenticationProperties == null) {
			btnAuthenticationProperties = new JButton();
			btnAuthenticationProperties
					.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(AuthenticationConfigurationChecklistPanel.class
							.getResource("/org/zaproxy/zap/extension/authenticationhelper/resources/gear.png"))));

			btnAuthenticationProperties.setToolTipText("Authentication method properties");
			btnAuthenticationProperties.setPreferredSize(new Dimension(PREFERED_WIDTH, PREFERED_HEIGHT));

			btnAuthenticationProperties.addActionListener(new java.awt.event.ActionListener() {
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					settingsBtnPressed();
					showAuthenticationPropertiesDialog();
				}
			});
		}
		return btnAuthenticationProperties;
	}

	private JButton getBtnUser() {
		if (btnUserProperties == null) {
			btnUserProperties = new JButton();
			btnUserProperties
					.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(AuthenticationConfigurationChecklistPanel.class
							.getResource("/org/zaproxy/zap/extension/authenticationhelper/resources/gear.png"))));

			btnUserProperties.setToolTipText("User properties");
			btnUserProperties.setPreferredSize(new Dimension(PREFERED_WIDTH, PREFERED_HEIGHT));

			btnUserProperties.addActionListener(new java.awt.event.ActionListener() {
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					settingsBtnPressed();
					showUserPropertiesDialog();
				}
			});
		}
		return btnUserProperties;
	}

	private void showUserPropertiesDialog() {
		View.getSingleton().showSessionDialog(Model.getSingleton().getSession(), getUserPaneName());
	}

	private String getUserPaneName() {
		return getSelectedContext().getIndex() + ": Users";
	}

	private JButton getBtnIndicator() {
		if (btnIndicatorProperties == null) {
			btnIndicatorProperties = new JButton();
			btnIndicatorProperties
					.setIcon(DisplayUtils.getScaledIcon(new ImageIcon(AuthenticationConfigurationChecklistPanel.class
							.getResource("/org/zaproxy/zap/extension/authenticationhelper/resources/gear.png"))));

			btnIndicatorProperties.setToolTipText("Indicator properties");
			btnIndicatorProperties.setPreferredSize(new Dimension(25, 25));

			btnIndicatorProperties.addActionListener(e -> {
				settingsBtnPressed();
				showAuthenticationPropertiesDialog();

			});
		}
		return btnIndicatorProperties;
	}

	private void showAuthenticationPropertiesDialog() {
		View.getSingleton().showSessionDialog(Model.getSingleton().getSession(), getAuthenticationPaneName());
	}

	private String getAuthenticationPaneName() {
		return getSelectedContext().getIndex() + ": Authentication";
	}

	private AuthenticationMethod getConfiguredAuthenticationMethod() {
		return getSelectedContext().getAuthenticationMethod();
	}

	private boolean noOrBadTarget() {
		return helperDialog.getTarget() == null || helperDialog.getTarget().getStartNode() == null;
	}

	private User getSelectedUser() {
		return helperDialog.getSelectedUser();
	}
}
