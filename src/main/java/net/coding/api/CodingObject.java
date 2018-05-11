package net.coding.api;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

import java.lang.reflect.Field;

public class CodingObject {

    protected String url;
    protected int id;
    protected String created_at;
    protected String updated_at;

    /**
     * String representation to assist debugging and inspection. The output format of this string
     * is not a committed part of the API and is subject to change.
     */
    @Override
    public String toString() {
        return new ReflectionToStringBuilder(this, TOSTRING_STYLE, null, null, false, false) {
            @Override
            protected boolean accept(Field field) {
                return super.accept(field) && !field.isAnnotationPresent(SkipFromToString.class);
            }
        }.toString();
    }

    private static final ToStringStyle TOSTRING_STYLE = new ToStringStyle() {
        {
            this.setUseShortClassName(true);
        }

        @Override
        public void append(StringBuffer buffer, String fieldName, Object value, Boolean fullDetail) {
            // skip unimportant properties. '_' is a heuristics as important properties tend to have short names
            if (fieldName.contains("_"))
                return;
            // avoid recursing other GHObject
            if (value instanceof CodingObject)
                return;
            // likewise no point in showing root
            if (value instanceof Coding)
                return;

            super.append(buffer,fieldName,value,fullDetail);
        }
    };
}
