package net.coding.api;

public class CodingOrganization extends CodingPerson {
    /*package*/ CodingOrganization wrapUp(Coding root) {
        return (CodingOrganization)super.wrapUp(root);
    }
}
