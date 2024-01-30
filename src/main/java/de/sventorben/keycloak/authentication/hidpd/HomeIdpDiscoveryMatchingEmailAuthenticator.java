package de.sventorben.keycloak.authentication.hidpd;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Optional;

public class HomeIdpDiscoveryMatchingEmailAuthenticator implements ConditionalAuthenticator {
    private static final Logger LOG = Logger.getLogger(HomeIdpDiscoveryMatchingEmailAuthenticatorFactory.class);

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticationSessionModel clientSession = context.getAuthenticationSession();

        SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(clientSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        if (serializedCtx == null) {
            throw new AuthenticationFlowException("Not found serialized context in clientSession", AuthenticationFlowError.IDENTITY_PROVIDER_ERROR);
        }
        BrokeredIdentityContext brokerContext = serializedCtx.deserialize(context.getSession(), clientSession);
        String providerId = brokerContext.getIdpConfig().getProviderId();

        LOG.info("Checking if email matches idp " + serializedCtx.getEmail());
        LOG.info("Broker username" + serializedCtx.getBrokerUsername());
        LOG.info("Model username" + serializedCtx.getModelUsername());

        Optional<IdentityProviderModel> homeIdp = new HomeIdpDiscoverer(context).discoverForUser(serializedCtx.getEmail());
        boolean matchesEmail = homeIdp.map(x -> x.isEnabled() && x.getProviderId().equals(providerId)).orElse(false);

        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
        if (authConfig!=null && authConfig.getConfig()!=null) {
            boolean negateOutput = Boolean.parseBoolean(authConfig.getConfig().get(HomeIdpDiscoveryMatchingEmailAuthenticatorFactory.CONF_NEGATE));
            return negateOutput != matchesEmail;
        }

        return matchesEmail;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // Not used
    }
}

