package de.sventorben.keycloak.authentication.hidpd;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

final class HomeIdpDiscoverer {

    private static final Logger LOG = Logger.getLogger(HomeIdpDiscoverer.class);

    private final DomainExtractor domainExtractor;

    private final KeycloakSession session;

    private final AuthenticationSessionModel authenticationSession;

    private final RealmModel realm;

    private final AuthenticatorConfigModel authenticatorConfig;

    private final UserModel userInContext;

    HomeIdpDiscoverer(AuthenticationFlowContext context) {
        this(new DomainExtractor(new HomeIdpDiscoveryConfig(context.getAuthenticatorConfig())), context);
    }


    HomeIdpDiscoverer(DomainExtractor domainExtractor, AuthenticationFlowContext context) {
        this(domainExtractor, context.getSession(), context.getAuthenticationSession(), context.getRealm(), context.getAuthenticatorConfig(), context.getUser());
    }

    HomeIdpDiscoverer(ValidationContext context) {
        this(new DomainExtractor(new HomeIdpDiscoveryConfig(null)), context.getSession(), context.getAuthenticationSession(), context.getRealm(), null, null);
    }

    HomeIdpDiscoverer(DomainExtractor domainExtractor, KeycloakSession session, AuthenticationSessionModel authenticationSession, RealmModel realm, AuthenticatorConfigModel authenticatorConfig, UserModel userInContext) {
        this.domainExtractor = domainExtractor;
        this.session = session;
        this.authenticationSession = authenticationSession;
        this.realm = realm;
        this.authenticatorConfig = authenticatorConfig;
        this.userInContext = userInContext;
    }

    public Optional<IdentityProviderModel> discoverForUser(String username) {
        Optional<IdentityProviderModel> homeIdp = Optional.empty();

        final Optional<String> emailDomain;
        if (userInContext == null) {
            emailDomain = domainExtractor.extractFrom(username);
        } else {
            emailDomain = domainExtractor.extractFrom(userInContext);
        }

        if (emailDomain.isPresent()) {
            String domain = emailDomain.get();
            homeIdp = discoverHomeIdp(domain, userInContext, username);
            if (homeIdp.isEmpty()) {
                LOG.tracef("Could not find home IdP for domain %s and user %s", domain, username);
            }
        } else {
            LOG.warnf("Could not extract domain from email address %s", username);
        }

        return homeIdp;
    }

    private Optional<IdentityProviderModel> discoverHomeIdp(String domain, UserModel user, String username) {
        final Map<String, String> linkedIdps;

        HomeIdpDiscoveryConfig config = new HomeIdpDiscoveryConfig(authenticatorConfig);
        if (user == null || !config.forwardToLinkedIdp()) {
            linkedIdps = Collections.emptyMap();
        } else {
            linkedIdps = session.users()
                .getFederatedIdentitiesStream(realm, user)
                .collect(
                    Collectors.toMap(FederatedIdentityModel::getIdentityProvider, FederatedIdentityModel::getUserName));
        }

        // enabled IdPs with domain
        List<IdentityProviderModel> idpsWithDomain = realm.getIdentityProvidersStream()
            .filter(IdentityProviderModel::isEnabled)
            .filter(it -> new IdentityProviderModelConfig(it).hasDomain(config.userAttribute(), domain))
            .collect(Collectors.toList());

        // Linked IdPs with matching domain
        Optional<IdentityProviderModel> homeIdp = idpsWithDomain.stream()
            .filter(it -> linkedIdps.containsKey(it.getAlias()))
            .findFirst();

        // linked and enabled IdPs
        if (homeIdp.isEmpty() && !linkedIdps.isEmpty()) {
            homeIdp = realm.getIdentityProvidersStream()
                .filter(IdentityProviderModel::isEnabled)
                .filter(it -> linkedIdps.containsKey(it.getAlias()))
                .findFirst();
        }

        // Matching domain
        if (homeIdp.isEmpty()) {
            homeIdp = idpsWithDomain.stream().findFirst();
        }

        homeIdp.ifPresent(it -> {
            if (linkedIdps.containsKey(it.getAlias()) && config.forwardToLinkedIdp()) {
                String idpUsername = linkedIdps.get(it.getAlias());
                authenticationSession.setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, idpUsername);
            } else {
                authenticationSession.setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, username);
            }
        });

        return homeIdp;
    }

}
