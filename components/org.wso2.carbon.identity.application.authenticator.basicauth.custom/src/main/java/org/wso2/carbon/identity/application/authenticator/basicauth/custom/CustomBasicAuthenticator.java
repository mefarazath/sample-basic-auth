/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.basicauth.custom;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
//import org.wso2.carbon.identity.application.authenticator.requestpath.basicauth.internal.BasicAuthRequestPathAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.basicauth.custom.internal.JWTBasicAuthenticatorServiceComponentDataHolder;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CustomBasicAuthenticator extends BasicAuthenticator {

    private static Log log = LogFactory.getLog(CustomBasicAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside canHandle()");
        }

        String headerValue = request.getHeader("Authorization");
        if (headerValue != null && !"".equals(headerValue.trim())) {
            String[] headerPart = headerValue.trim().split(" ");
            return "Basic".equals(headerPart[0]);
        } else {
            return request.getParameter("sectoken") != null;
        }

    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String headerValue = request.getHeader("Authorization");
        String credential = null;
        if (headerValue != null) {
            credential = headerValue.trim().split(" ")[1];
        } else {
            credential = request.getParameter("sectoken");
        }

        String credentials = new String(Base64.getDecoder().decode(credential));
        String username = credentials.substring(0, credentials.indexOf(":"));
        String password = credentials.substring(credentials.indexOf(":") + 1);
        if (!StringUtils.isBlank(username) && !StringUtils.isBlank(password)) {
            try {
                int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                UserStoreManager userStoreManager =
                        (UserStoreManager) JWTBasicAuthenticatorServiceComponentDataHolder.getInstance()
                                .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
                boolean isAuthenticated = userStoreManager.authenticate(MultitenantUtils.getTenantAwareUsername(username), password);
                if (!isAuthenticated) {
                    throw new InvalidCredentialsException("Authentication Failed", User.getUserFromUserName(username));
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Authenticated user " + username);
                    }

                    Map<String, Object> authProperties = context.getProperties();
                    String tenantDomain = MultitenantUtils.getTenantDomain(username);
                    if (authProperties == null) {
                        authProperties = new HashMap<>();
                        context.setProperties(authProperties);
                    }

                    authProperties.put("user-tenant-domain", tenantDomain);
                    context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(FrameworkUtils.prependUserStoreDomainToName(username)));
                }
            } catch (InvalidCredentialsException ex) {
                if (log.isDebugEnabled()) {
                    log.debug("BasicAuthentication failed for the user " + username, ex);
                }
                throw ex;
            } catch (IdentityRuntimeException ex) {
                if (log.isDebugEnabled()) {
                    log.debug("BasicAuthentication failed while trying to get the tenant ID of the user " + username, ex);
                }

                throw new AuthenticationFailedException(ex.getMessage(), User.getUserFromUserName(username), ex);
            } catch (Exception ex) {
                log.error(ex.getMessage(), ex);
                throw new AuthenticationFailedException("Authentication Failed", User.getUserFromUserName(username));
            }
        } else {
            throw new AuthenticationFailedException("username and password cannot be empty", User.getUserFromUserName(username));
        }

    }

    @Override
    public String getFriendlyName() {
        return "custom-basic-requestpath";
    }

    @Override
    public String getName() {
        return "CustomBasicRequestPathAuthenticator";
    }
}
