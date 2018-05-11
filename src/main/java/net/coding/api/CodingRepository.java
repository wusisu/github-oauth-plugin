package net.coding.api;

import java.io.IOException;

public class CodingRepository {
    /*package almost final*/ Coding root;

    private String description, homepage, name, full_name;
    private String html_url;    // this is the UI

    private CodingUser owner;   // not fully populated. beware.

    private boolean _private;
    private boolean permissions_pull;
    private boolean permissions_push;
    private boolean permissions_admin;

    /**
     * Short repository name without the owner. For example 'jenkins' in case of http://github.com/jenkinsci/jenkins
     */
    public String getName() {
        return name;
    }

    /*package*/ CodingRepository wrap(Coding root) {
        this.root = root;
        return this;
    }

    public CodingUser getOwner() throws IOException {
        return root.getUser(owner.getLogin());   // because 'owner' isn't fully populated
    }

    public boolean isPrivate() {
        return _private;
    }

    public boolean hasPullAccess() {
        return permissions_pull;
    }

    public boolean hasPushAccess() {
        return permissions_push;
    }

    public boolean hasAdminAccess() {
        return permissions_admin;
    }
}
