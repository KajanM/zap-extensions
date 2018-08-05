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
package org.zaproxy.zap.extension.authenticationhelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.configuration.FileConfiguration;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.authenticationhelper.autoconfig.AuthenticationAutoConfigurationParam;

public class OptionsParamAuthenticationHelper extends AbstractParam {

	private static final String CONFIRM_REMOVE_EXCLUDE_REGEX_KEY = "authenticationhelper.confirmRemoveProxyExcludeRegex";
	private static final String REGEXES_TO_IGNORE_KEY = "authenticationhelper.regexestoignore";
	private static final String AUTO_CONFIGURED_PARAMS_KEY = "authenticationhelper.autoconfigs";

	private boolean confirmRemoveExcludeRegex;
	private List<String> regexesToIgnore;

	/**
	 * The {@link AuthenticationAutoConfigurationParam} mapped to the
	 * {@code String, domain}.
	 * <p>
	 * It is used as a hack to allow pen tester to set {@code username} and
	 * {@code password} in headless mode, when auto configuring authentication.
	 * <p>
	 * This variable is destroyed on session change event and when shutting down ZAP.
	 */
	private Map<String, AuthenticationAutoConfigurationParam> autoConfiguredParams;

	//@formatter:off
	private static final String[] DEFAULT_PATTERNS_TO_IGNORE = { ".*.css", 
																 ".*.js", 
																 ".*.jpeg",
																 ".*.jpg",
																 ".*.png",
																 ".*.ico",
																 ".*logout.*",
																 ".*login.*"};
	//@formatter:on

	public OptionsParamAuthenticationHelper() {
	}

	@SuppressWarnings("unchecked")
	@Override
	protected void parse() {
		FileConfiguration cfg = getConfig();
		confirmRemoveExcludeRegex = cfg.getBoolean(CONFIRM_REMOVE_EXCLUDE_REGEX_KEY, false);
		regexesToIgnore = (List<String>) (List<?>) cfg.getList(REGEXES_TO_IGNORE_KEY);
		addDefaultIgnoredRegexes();
		// no need to parse autoConfiguredParams
	}

	private void addDefaultIgnoredRegexes() {
		regexesToIgnore.addAll(Arrays.asList(DEFAULT_PATTERNS_TO_IGNORE));
		regexesToIgnore = regexesToIgnore.stream().distinct().collect(Collectors.toList());
	}

	public boolean isConfirmRemoveExcludeRegex() {
		return confirmRemoveExcludeRegex;
	}

	public void setConfirmRemoveExcludeRegex(boolean confirmRemove) {
		this.confirmRemoveExcludeRegex = confirmRemove;
		getConfig().setProperty(CONFIRM_REMOVE_EXCLUDE_REGEX_KEY, Boolean.valueOf(confirmRemove));
	}

	public List<String> getRegexesToIgnore() {
		return regexesToIgnore;
	}

	public void setRegexesToIgnore(List<String> regexesToIgnore) {
		addDefaultIgnoredRegexes();
		getConfig().setProperty(REGEXES_TO_IGNORE_KEY, regexesToIgnore);
	}

	public List<Pattern> getRexesPatternsToIgnore() {
		List<Pattern> regexPatternsToIgnore = new ArrayList<>();
		for (String regex : regexesToIgnore) {
			if (regex.trim().length() > 0) {
				regexPatternsToIgnore.add(Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE));
			}
		}
		return regexPatternsToIgnore;
	}

	public void addAutoConfiguredParam(AuthenticationAutoConfigurationParam autoConfiguredParam) {
		if (autoConfiguredParam == null) {
			throw new IllegalArgumentException("The params cannot be null");
		}
		getAutoConfiguredParams().put(autoConfiguredParam.getDomain(), autoConfiguredParam);
		saveAutoConfiguredParams();
	}

	public Map<String, AuthenticationAutoConfigurationParam> getAutoConfiguredParams() {
		if (autoConfiguredParams == null) {
			autoConfiguredParams = new HashMap<>();
		}
		return autoConfiguredParams;
	}

	public AuthenticationAutoConfigurationParam getAutoConfiguredParam(String domain) {
		return getAutoConfiguredParams().get(domain);
	}

	public void eraseAutoConfiguredParams() {
		autoConfiguredParams = null;
		saveAutoConfiguredParams();
	}
	
	public void saveAutoConfiguredParams() {
		getConfig().setProperty(AUTO_CONFIGURED_PARAMS_KEY, autoConfiguredParams);
	}
}
