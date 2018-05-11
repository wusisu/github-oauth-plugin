package net.coding.api;

import java.io.IOException;

public class CodingOrganization extends CodingPerson {
    protected String login, avatar_url, gravatar_id;

    /*package*/ CodingOrganization wrapUp(Coding root) {
        return (CodingOrganization)super.wrapUp(root);
    }

    /**
     * Finds a team that has the given name in its {@link CodingTeam#getName()}
     */
    public CodingTeam getTeamByName(String name) throws IOException {
        for (CodingTeam t : listTeams()) {
            if(t.getName().equals(name))
                return t;
        }
        return null;
    }

    /**
     * List up all the teams.
     */
    public PagedIterable<CodingTeam> listTeams() throws IOException {
        return new PagedIterable<CodingTeam>() {
            public PagedIterator<CodingTeam> _iterator(int pageSize) {
                return new PagedIterator<CodingTeam>(root.retrieve().asIterator(String.format("/orgs/%s/teams", getLogin()), CodingTeam[].class, pageSize)) {
                    @Override
                    protected void wrapUp(CodingTeam[] page) {
                        for (CodingTeam c : page)
                            c.wrapUp(CodingOrganization.this);
                    }
                };
            }
        };
    }
}
