package de.sventorben.keycloak.authentication.hidpd;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationSelectionOption;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class HomeIdpDiscoveryRegistrationEmail implements FormAction, FormActionFactory {
    public static final String PROVIDER_ID = "registration-email-idp-action";

    public static final String ERROR_EMAIL_BOUND_TO_IDP = "emailBoundToIdp";

    @Override
    public String getHelpText() {
        return "Validates that email domain is not bound to an IDP.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        if (formData.getFirst(RegistrationPage.FIELD_EMAIL) != null) {
            HomeIdpDiscoverer discoverer = new HomeIdpDiscoverer(new AuthenticationFlowContextAdapter(context));
            List<IdentityProviderModel> idp = discoverer.discoverForUser(formData.getFirst(RegistrationPage.FIELD_EMAIL));
            if (!idp.isEmpty()) {
                errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, ERROR_EMAIL_BOUND_TO_IDP));
            }
        }

        if (errors.size() > 0) {
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            return;
        } else {
            context.success();
        }
    }

    @Override
    public void success(FormContext context) {

    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Home IdP Discovery (Email Validation)";
    }

    @Override
    public String getReferenceCategory() {
        return "Authorization";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    public static class AuthenticationFlowContextAdapter implements AuthenticationFlowContext {

        private final ValidationContext context;

        public AuthenticationFlowContextAdapter(ValidationContext context) {
            this.context = context;
        }

        @Override
        public UserModel getUser() {
            return null;
        }

        @Override
        public void setUser(UserModel userModel) {

        }

        @Override
        public List<AuthenticationSelectionOption> getAuthenticationSelections() {
            return null;
        }

        @Override
        public void setAuthenticationSelections(List<AuthenticationSelectionOption> list) {

        }

        @Override
        public void clearUser() {

        }

        @Override
        public void attachUserSession(UserSessionModel userSessionModel) {

        }

        @Override
        public AuthenticationSessionModel getAuthenticationSession() {
            return null;
        }

        @Override
        public String getFlowPath() {
            return null;
        }

        @Override
        public LoginFormsProvider form() {
            return null;
        }

        @Override
        public URI getActionUrl(String s) {
            return null;
        }

        @Override
        public URI getActionTokenUrl(String s) {
            return null;
        }

        @Override
        public URI getRefreshExecutionUrl() {
            return null;
        }

        @Override
        public URI getRefreshUrl(boolean b) {
            return null;
        }

        @Override
        public void cancelLogin() {

        }

        @Override
        public void resetFlow() {

        }

        @Override
        public void resetFlow(Runnable runnable) {

        }

        @Override
        public void fork() {

        }

        @Override
        public void forkWithSuccessMessage(FormMessage formMessage) {

        }

        @Override
        public void forkWithErrorMessage(FormMessage formMessage) {

        }

        @Override
        public EventBuilder getEvent() {
            return null;
        }

        @Override
        public EventBuilder newEvent() {
            return null;
        }

        @Override
        public AuthenticationExecutionModel getExecution() {
            return null;
        }

        @Override
        public RealmModel getRealm() {
            return context.getRealm();
        }

        @Override
        public ClientConnection getConnection() {
            return null;
        }

        @Override
        public UriInfo getUriInfo() {
            return null;
        }

        @Override
        public KeycloakSession getSession() {
            return context.getSession();
        }

        @Override
        public HttpRequest getHttpRequest() {
            return null;
        }

        @Override
        public BruteForceProtector getProtector() {
            return null;
        }

        @Override
        public AuthenticatorConfigModel getAuthenticatorConfig() {
            return null;
        }

        @Override
        public FormMessage getForwardedErrorMessage() {
            return null;
        }

        @Override
        public FormMessage getForwardedSuccessMessage() {
            return null;
        }

        @Override
        public FormMessage getForwardedInfoMessage() {
            return null;
        }

        @Override
        public void setForwardedInfoMessage(String s, Object... objects) {

        }

        @Override
        public String generateAccessCode() {
            return null;
        }

        @Override
        public AuthenticationExecutionModel.Requirement getCategoryRequirementFromCurrentFlow(String s) {
            return null;
        }

        @Override
        public void success() {

        }

        @Override
        public void failure(AuthenticationFlowError authenticationFlowError) {

        }

        @Override
        public void failure(AuthenticationFlowError authenticationFlowError, Response response) {

        }

        @Override
        public void failure(AuthenticationFlowError authenticationFlowError, Response response, String s, String s1) {

        }

        @Override
        public void challenge(Response response) {

        }

        @Override
        public void forceChallenge(Response response) {

        }

        @Override
        public void failureChallenge(AuthenticationFlowError authenticationFlowError, Response response) {

        }

        @Override
        public void attempted() {

        }

        @Override
        public FlowStatus getStatus() {
            return null;
        }

        @Override
        public AuthenticationFlowError getError() {
            return null;
        }

        @Override
        public String getEventDetails() {
            return null;
        }

        @Override
        public String getUserErrorMessage() {
            return null;
        }
    }
}
