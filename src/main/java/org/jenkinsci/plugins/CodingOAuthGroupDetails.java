/**
 *
 */
package org.jenkinsci.plugins;

import hudson.security.GroupDetails;
import net.coding.api.CodingOrganization;
import net.coding.api.CodingTeam;

/**
 * @author Mike
 *
 */
public class CodingOAuthGroupDetails extends GroupDetails {

    private final CodingOrganization org;
    private final CodingTeam team;
    static final String ORG_TEAM_SEPARATOR = "*";

    /**
    * Group based on organization name
    * @param org the github organization
    */
    public CodingOAuthGroupDetails(CodingOrganization org) {
        super();
        this.org = org;
        this.team = null;
    }

    /**
    * Group based on team name
     * @param team the github team
     */
    public CodingOAuthGroupDetails(CodingTeam team) {
        super();
        this.org = team.getOrganization();
        this.team = team;
    }

    /* (non-Javadoc)
    * @see hudson.security.GroupDetails#getName()
    */
    @Override
    public String getName() {
        if (team != null)
            return org.getLogin() + ORG_TEAM_SEPARATOR + team.getName();
        if (org != null)
            return org.getLogin();
        return null;
    }

}
