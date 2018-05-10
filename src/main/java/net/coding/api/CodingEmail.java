package net.coding.api;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

@SuppressFBWarnings(value = {"UWF_UNWRITTEN_PUBLIC_OR_PROTECTED_FIELD", "UWF_UNWRITTEN_FIELD",
        "NP_UNWRITTEN_FIELD", "NP_UNWRITTEN_PUBLIC_OR_PROTECTED_FIELD"}, justification = "JSON API")
public class CodingEmail {

    protected String email;
    protected boolean primary;
    protected boolean verified;

    public String getEmail() {
        return email;
    }

    public boolean isPrimary() {
        return primary;
    }

    public boolean isVerified() {
        return verified;
    }


    @Override
    public String toString() {
        return "Email:"+email;
    }

    @Override
    public int hashCode() {
        return email.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof CodingEmail) {
            CodingEmail that = (CodingEmail) obj;
            return this.email.equals(that.email);
        }
        return false;
    }
}
