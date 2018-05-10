/**
 The MIT License

Copyright (c) 2015 Sam Gleske

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

package org.jenkinsci.plugins;

import org.jenkinsci.plugins.CodingSecurityRealm.DescriptorImpl;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class CodingSecurityRealmTest {

    @ClassRule
    public final static JenkinsRule rule = new JenkinsRule();

    @Test
    public void testEquals_true() {
        CodingSecurityRealm a = new CodingSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "team");
        CodingSecurityRealm b = new CodingSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "team");
        assertTrue(a.equals(b));
    }

    @Test
    public void testEquals_false() {
        CodingSecurityRealm a = new CodingSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "team");
        CodingSecurityRealm b = new CodingSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "team,repo");
        assertFalse(a.equals(b));
        assertFalse(a.equals(""));
    }

    @Test
    public void testHasScope_true() {
        CodingSecurityRealm a = new CodingSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "team,user,user:email");
        assertTrue(a.hasScope("user"));
        assertTrue(a.hasScope("team")); //read:org
        assertTrue(a.hasScope("user:email"));
    }

    @Test
    public void testHasScope_false() {
        CodingSecurityRealm a = new CodingSecurityRealm("http://jenkins.acme.com", "http://jenkins.acme.com/api/v3", "someid", "somesecret", "team,user,user:email");
        assertFalse(a.hasScope("somescope"));
    }

    @Test
    public void testDescriptorImplGetDefaultGithubWebUri() {
        DescriptorImpl descriptor = new DescriptorImpl();
        assertTrue("https://coding.net".equals(descriptor.getDefaultGithubWebUri()));
    }

    @Test
    public void testDescriptorImplGetDefaultGithubApiUri() {
        DescriptorImpl descriptor = new DescriptorImpl();
        assertTrue("https://coding.net".equals(descriptor.getDefaultGithubApiUri()));
    }

    @Test
    public void testDescriptorImplGetDefaultOauthScopes() {
        DescriptorImpl descriptor = new DescriptorImpl();
        assertTrue("user,user:email,team".equals(descriptor.getDefaultOauthScopes()));
    }
}
