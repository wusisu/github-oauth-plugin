/*
 * The MIT License
 *
 * Copyright (c) 2017, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins;

import hudson.model.User;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runners.model.Statement;
import org.jvnet.hudson.test.RestartableJenkinsRule;

public class CodingSecretStorageTest {

    @Rule
    public RestartableJenkinsRule j = new RestartableJenkinsRule();

    @Test
    public void correctBehavior() throws Exception {
        j.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                User.getById("alice", true);
                User.getById("bob", true);

                String secret = "$3cR3t";

                Assert.assertFalse(CodingSecretStorage.contains(retrieveUser()));
                Assert.assertNull(CodingSecretStorage.retrieve(retrieveUser()));

                Assert.assertFalse(CodingSecretStorage.contains(retrieveOtherUser()));

                CodingSecretStorage.put(retrieveUser(), secret);

                Assert.assertTrue(CodingSecretStorage.contains(retrieveUser()));
                Assert.assertFalse(CodingSecretStorage.contains(retrieveOtherUser()));

                Assert.assertEquals(secret, CodingSecretStorage.retrieve(retrieveUser()));
            }
        });
    }

    private User retrieveUser() {
        return User.getById("alice", false);
    }

    private User retrieveOtherUser() {
        return User.getById("bob", false);
    }

    @Test
    public void correctBehaviorEvenAfterRestart() throws Exception {
        final String secret = "$3cR3t";

        j.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                User.getById("alice", true).save();
                User.getById("bob", true).save();

                Assert.assertFalse(CodingSecretStorage.contains(retrieveUser()));
                Assert.assertNull(CodingSecretStorage.retrieve(retrieveUser()));

                Assert.assertFalse(CodingSecretStorage.contains(retrieveOtherUser()));

                CodingSecretStorage.put(retrieveUser(), secret);

                Assert.assertTrue(CodingSecretStorage.contains(retrieveUser()));
                Assert.assertFalse(CodingSecretStorage.contains(retrieveOtherUser()));

                Assert.assertEquals(secret, CodingSecretStorage.retrieve(retrieveUser()));
            }
        });
        j.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                Assert.assertTrue(CodingSecretStorage.contains(retrieveUser()));
                Assert.assertFalse(CodingSecretStorage.contains(retrieveOtherUser()));

                Assert.assertEquals(secret, CodingSecretStorage.retrieve(retrieveUser()));
            }
        });
    }
}
