package org.picketlink.test.identity.federation.bindings.wildfly;

import io.undertow.servlet.api.ClassIntrospecter;
import io.undertow.servlet.api.InstanceFactory;
import io.undertow.servlet.util.ConstructorInstanceFactory;

/**
 * @author Stuart Douglas
 */
public class TestClassIntrospector implements ClassIntrospecter {

    public static final TestClassIntrospector INSTANCE = new TestClassIntrospector();

    @Override
    public <T> InstanceFactory<T> createInstanceFactory(final Class<T> clazz) {
        try {
            return new ConstructorInstanceFactory<T>(clazz.getDeclaredConstructor());
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }
}
