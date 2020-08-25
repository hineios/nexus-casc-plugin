package io.github.asharapov.nexus.casc.internal;

import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class InterpolatorTest {

    @Test
    void interpolateWithFile() {
        final URL url = getClass().getClassLoader().getResource("test");
        assertNotNull(url);
        assertEquals("hello world", new Interpolator().interpolate("hello ${file:"+url.getPath()+"}"));
    }

    @Test
    void interpolateWithEnvVar() {
        Map.Entry<String, String> envVar = System.getenv().entrySet().iterator().next();
        String key = envVar.getKey();
        String value = envVar.getValue();

        assertEquals("hello " + value, new Interpolator().interpolate("hello $"+key));
        assertEquals("hello " + value, new Interpolator().interpolate("hello ${"+key+"}"));
        assertEquals("hello " + value, new Interpolator().interpolate("hello ${"+key+":\"\"}"));
        assertEquals("hello " + value, new Interpolator().interpolate("hello ${"+key+":}"));
        assertEquals("hello " + value, new Interpolator().interpolate("hello ${"+key+":foo}"));
    }

    @Test
    void interpolateWithNonExistingEnvVar() {
        assertEquals("hello $IDONOTEXIST", new Interpolator().interpolate("hello $IDONOTEXIST"));
        assertEquals("hello ${IDONOTEXIST}", new Interpolator().interpolate("hello ${IDONOTEXIST}"));
        assertEquals("hello ", new Interpolator().interpolate("hello ${IDONOTEXIST:}"));
        assertEquals("hello ", new Interpolator().interpolate("hello ${IDONOTEXIST:\"\"}"));
        assertEquals("hello world", new Interpolator().interpolate("hello ${IDONOTEXIST:world}"));
        assertEquals("hello world", new Interpolator().interpolate("hello ${IDONOTEXIST:\"world\"}"));
    }
}
