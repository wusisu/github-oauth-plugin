package net.coding.api;

public class CodingRepository {
    /*package almost final*/ Coding root;

    private String description, homepage, name, full_name;
    private String html_url;    // this is the UI

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
}
