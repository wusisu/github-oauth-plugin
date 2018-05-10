package org.jenkinsci.plugins;

import jenkins.model.Jenkins;
import net.coding.api.Coding;
import net.coding.api.CodingBuilder;
import net.coding.api.CodingMyself;
import net.coding.api.extras.OkHttpConnector;
import org.apache.commons.lang.SerializationUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Coding.class, CodingBuilder.class, Jenkins.class, CodingSecurityRealm.class})
public class CodingAuthenticationTokenTest {

    @Mock
    private Jenkins jenkins;

    @Mock
    private CodingSecurityRealm securityRealm;

    @Before
    public void setUp() throws Exception {
        PowerMockito.mockStatic(Jenkins.class);
        PowerMockito.when(Jenkins.getInstance()).thenReturn(jenkins);
        PowerMockito.when(jenkins.getSecurityRealm()).thenReturn(securityRealm);
        PowerMockito.when(securityRealm.getOauthScopes()).thenReturn("user,user:email,team");
    }

    @Test
    public void testTokenSerialization() throws IOException {
        mockCodingMyselfAs("bob");
        CodingAuthenticationToken authenticationToken = new CodingAuthenticationToken("accessToken", "https://coding.net");
        byte[] serializedToken = SerializationUtils.serialize(authenticationToken);
        CodingAuthenticationToken deserializedToken = (CodingAuthenticationToken) SerializationUtils.deserialize(serializedToken);
        assertEquals(deserializedToken.getAccessToken(), authenticationToken.getAccessToken());
        assertEquals(deserializedToken.getPrincipal(), authenticationToken.getPrincipal());
        assertEquals(deserializedToken.getGithubServer(), authenticationToken.getGithubServer());
        assertEquals(deserializedToken.getMyself().getLogin(), deserializedToken.getMyself().getLogin());
    }

    @After
    public void after() {
        CodingAuthenticationToken.clearCaches();
    }

    private CodingMyself mockCodingMyselfAs(String username) throws IOException {
        Coding gh = PowerMockito.mock(Coding.class);
        CodingBuilder builder = PowerMockito.mock(CodingBuilder.class);
        PowerMockito.mockStatic(Coding.class);
        PowerMockito.mockStatic(CodingBuilder.class);
        PowerMockito.when(CodingBuilder.fromEnvironment()).thenReturn(builder);
        PowerMockito.when(builder.withEndpoint("https://coding.net")).thenReturn(builder);
        PowerMockito.when(builder.withOAuthToken("accessToken")).thenReturn(builder);
//        PowerMockito.when(builder.withRateLimitHandler(RateLimitHandler.FAIL)).thenReturn(builder);
        PowerMockito.when(builder.withConnector(Mockito.any(OkHttpConnector.class))).thenReturn(builder);
        PowerMockito.when(builder.build()).thenReturn(gh);
        CodingMyself me = PowerMockito.mock(CodingMyself.class);
        PowerMockito.when(gh.getMyself()).thenReturn(me);
        PowerMockito.when(me.getLogin()).thenReturn(username);
        return me;
    }

}
