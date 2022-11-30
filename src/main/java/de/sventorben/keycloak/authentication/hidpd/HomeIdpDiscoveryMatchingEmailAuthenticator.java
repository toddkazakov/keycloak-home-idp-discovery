package de.sventorben.keycloak.authentication.hidpd;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Optional;

public class HomeIdpDiscoveryMatchingEmailAuthenticator extends AbstractIdpAuthenticator {

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext userCtx, BrokeredIdentityContext brokeredIdentityContext) {
        String providerId = brokeredIdentityContext.getIdpConfig().getProviderId();

        Optional<IdentityProviderModel> homeIdp = new HomeIdpDiscoverer(context).discoverForUser(userCtx.getEmail());
        boolean emailMatchesProvider = homeIdp.map(x -> x.getProviderId().equals(providerId)).orElse(false);
        if (emailMatchesProvider) {
            context.success();
            return;
        }

        context.attempted();
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext authenticationFlowContext, SerializedBrokeredIdentityContext serializedBrokeredIdentityContext, BrokeredIdentityContext brokeredIdentityContext) {
        authenticateImpl(authenticationFlowContext,serializedBrokeredIdentityContext, brokeredIdentityContext);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }
}

