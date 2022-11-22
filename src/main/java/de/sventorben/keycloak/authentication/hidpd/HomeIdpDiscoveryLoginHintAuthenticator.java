package de.sventorben.keycloak.authentication.hidpd;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

import java.util.Optional;

final class HomeIdpDiscoveryLoginHintAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(HomeIdpDiscoveryLoginHintAuthenticator.class);

    HomeIdpDiscoveryLoginHintAuthenticator() {
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String loginHint = null;
        if (context.getUriInfo().getQueryParameters().containsKey(OIDCLoginProtocol.LOGIN_HINT_PARAM)) {
            loginHint = context.getUriInfo().getQueryParameters().getFirst(OIDCLoginProtocol.LOGIN_HINT_PARAM);

            if (loginHint != null) {
                loginHint = loginHint.trim();
                if ("".equalsIgnoreCase(loginHint))
                    loginHint = null;
            }
        }

        if (loginHint == null) {
            LOG.tracef("No login hint query parameter provided");
            context.attempted();
            return;
        }

        final Optional<IdentityProviderModel> homeIdp = new HomeIdpDiscoverer(context).discoverForUser(loginHint);

        if (homeIdp.isEmpty()) {
            context.attempted();
        } else {
            new Redirector(context).redirectTo(homeIdp.get());
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

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
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }
}
