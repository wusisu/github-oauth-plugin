package net.coding.api;

public class CodingTeam {

    private String name,permission,slug;

    private CodingOrganization organization;

    protected /*final*/ CodingOrganization org;

    private String global_key, avatar;

    private Integer id;

    public CodingOrganization getOrganization() {
        return org;
    }

    /*package*/ CodingTeam wrapUp(CodingOrganization owner) {
        this.org = owner;
        return this;
    }

    /*package*/ CodingTeam wrapUp(Coding root) { // auto-wrapUp when organization is known from GET /user/teams
        if (this.organization == null) {
            this.organization = new CodingOrganization();
            this.organization.global_key = "coding_dot_net";
        }
        this.organization.wrapUp(root);
        return wrapUp(organization);
    }

    public String getName() {
        return name;
    }
}
