package net.coding.api;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import com.infradna.tool.bridge_method_injector.WithBridgeMethods;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.ANY;
import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.NONE;

public class Coding {
    /*package*/ final String login;

    private final Map<String,CodingUser> users = new Hashtable<String, CodingUser>();
    private final Map<String,CodingOrganization> orgs = new Hashtable<String, CodingOrganization>();

    private final String apiUrl;
    private HttpConnector connector = HttpConnector.DEFAULT;
    /*package*/ final String encodedAuthorization;

    Coding(String apiUrl, String login, String oauthAccessToken, String password, HttpConnector connector) throws IOException {
        if (apiUrl.endsWith("/")) apiUrl = apiUrl.substring(0, apiUrl.length()-1); // normalize
        this.apiUrl = apiUrl;
        if (null != connector) this.connector = connector;

        if (oauthAccessToken!=null) {
            encodedAuthorization = "token "+oauthAccessToken;
        } else {
            if (password!=null) {
                String authorization = (login + ':' + password);
                String charsetName = Charsets.UTF_8.name();
                encodedAuthorization = "Basic "+new String(Base64.encodeBase64(authorization.getBytes(charsetName)), charsetName);
            } else {// anonymous access
                encodedAuthorization = null;
            }
        }

        if (login==null && encodedAuthorization!=null)
            login = getMyself().getLogin();
        this.login = login;
    }

    /**
     * This method returns a shallowly populated organizations.
     *
     * To retrieve full organization details, you need to call {@link #getOrganization(String)}
     * TODO: make this automatic.
     */
    public Map<String, CodingOrganization> getMyOrganizations() throws IOException {
        if ("https://coding.net".equals(apiUrl)) {
            return Collections.singletonMap("coding_dot_net", null);
        }
        return Collections.singletonMap("coding_dot_net", null);
//        CodingOrganization[] orgs = retrieve().to("/user/orgs", CodingOrganization[].class);
//        Map<String, CodingOrganization> r = new HashMap<String, CodingOrganization>();
//        for (CodingOrganization o : orgs) {
//            // don't put 'o' into orgs because they are shallow
//            r.put(o.getLogin(),o.wrapUp(this));
//        }
//        return r;
    }

    public CodingOrganization getOrganization(String name) throws IOException {
        CodingOrganization o = new CodingOrganization();
        o.global_key = "coding_dot_net";
        return o;
//        CodingOrganization o = orgs.get(name);
//        if (o==null) {
//            o = retrieve().to("/orgs/" + name, CodingOrganization.class).wrapUp(this);
//            orgs.put(name,o);
//        }
//        return o;
    }

    /**
     * Gets the repository object from 'user/reponame' string that GitHub calls as "repository name"
     *
     * @see CodingRepository#getName()
     */
    public CodingRepository getRepository(String name) throws IOException {
        String[] tokens = name.split("/");
        return retrieve().to("/repos/" + tokens[0] + '/' + tokens[1], CodingRepository.class).wrap(this);
    }

    /**
     * Gets complete map of organizations/teams that current user belongs to.
     *
     * Leverages the new GitHub API /user/teams made available recently to
     * get in a single call the complete set of organizations, teams and permissions
     * in a single call.
     */
    public Map<String, Set<CodingTeam>> getMyTeams() throws IOException {
        Map<String, Set<CodingTeam>> allMyTeams = new HashMap<String, Set<CodingTeam>>();
        for (CodingTeam team : retrieve().to("/team/joined", CodingTeam[].class)) {
            team.wrapUp(this);
            String orgLogin = team.getOrganization().getLogin();
            Set<CodingTeam> teamsPerOrg = allMyTeams.get(orgLogin);
            if (teamsPerOrg == null) {
                teamsPerOrg = new HashSet<CodingTeam>();
            }
            teamsPerOrg.add(team);
            allMyTeams.put(orgLogin, teamsPerOrg);
        }
        return allMyTeams;
    }

    /**
     * Obtains the object that represents the named user.
     */
    public CodingUser getUser(String login) throws IOException {
        CodingUser u = users.get(login);
        if (u == null) {
            u = retrieve().to("/user/key/" + login, CodingUser.class);
            u.root = this;
            users.put(u.getLogin(), u);
        }
        return u;
    }


    /**
     * Gets the {@link CodingUser} that represents yourself.
     */
    @WithBridgeMethods(CodingUser.class)
    public CodingMyself getMyself() throws IOException {
        requireCredential();

        CodingMyself u = retrieve().to("/current_user", CodingMyself.class);

        u.root = this;
        users.put(u.getLogin(), u);

        return u;
    }

    /*package*/ void requireCredential() {
        if (isAnonymous())
            throw new IllegalStateException("This operation requires a credential but none is given to the GitHub constructor");
    }

    /**
     * Is this an anonymous connection
     * @return {@code true} if operations that require authentication will fail.
     */
    public boolean isAnonymous() {
        return login==null && encodedAuthorization==null;
    }

    Requester retrieve() {
        return new Requester(this).method("GET");
    }

    public HttpConnector getConnector() {
        return connector;
    }

    /*package*/ URL getApiURL(String tailApiUrl) throws IOException {
        if (tailApiUrl.startsWith("/")) {
            return new URL(apiUrl + tailApiUrl);
        } else {
            return new URL(tailApiUrl);
        }
    }

    /*package*/ static String printDate(Date dt) {
        return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(dt);
    }

    /*package*/ static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String[] TIME_FORMATS = {"yyyy/MM/dd HH:mm:ss ZZZZ","yyyy-MM-dd'T'HH:mm:ss'Z'"};

    static {
        MAPPER.setVisibilityChecker(new VisibilityChecker.Std(NONE, NONE, NONE, NONE, ANY));
        MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    /* package */ static final String CODING_URL = "https://coding.net";

    private static final Logger LOGGER = Logger.getLogger(Coding.class.getName());
}
