package net.coding.api;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

public class CodingPersonSet<T extends CodingPerson> extends HashSet<T> {
    private static final long serialVersionUID = 1L;

    public CodingPersonSet() {
    }

    public CodingPersonSet(Collection<? extends T> c) {
        super(c);
    }

    public CodingPersonSet(T... c) {
        super(Arrays.asList(c));
    }

    public CodingPersonSet(int initialCapacity, float loadFactor) {
        super(initialCapacity, loadFactor);
    }

    public CodingPersonSet(int initialCapacity) {
        super(initialCapacity);
    }

    /**
     * Finds the item by its login.
     */
    public T byLogin(String login) {
        for (T t : this)
            if (t.getLogin().equals(login))
                return t;
        return null;
    }
}
