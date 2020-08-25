package io.github.asharapov.nexus.casc.internal.utils;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.asharapov.nexus.casc.internal.Utils;
import okhttp3.Credentials;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Assertions;
import org.testcontainers.utility.MountableFile;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.concurrent.TimeUnit;

public class TestUtils {

    public static final MediaType YAML_TYPE = MediaType.get("text/vnd.yaml");
    public static final MediaType APPLICATION_JSON = MediaType.get("application/json");

    /**
     * @return the current process id
     */
    public static String getProcessId() {
        final String procName = ManagementFactory.getRuntimeMXBean().getName();
        return Utils.getHead(procName, '@');
    }

    public static MountableFile getCascPluginFile() {
        final File baseDir = new File("target").getAbsoluteFile();
        final FileFilter filter = new FileFilter() {
            @Override
            public boolean accept(final File file) {
                final String name = file.getName();
                return name.startsWith("nexus-casc-plugin-") && name.endsWith("-bundle.kar");
            }
        };
        final File[] files = baseDir.listFiles(filter);
        return files != null && files.length == 1
                ? MountableFile.forHostPath(files[0].getAbsolutePath())
                : null;
    }

    public static MountableFile[] getPemFiles() {
        return new MountableFile[]{
                MountableFile.forClasspathResource("/nexus/www-postgresql-org-chain.pem"),
                MountableFile.forClasspathResource("/nexus/www-redhat-com-chain.pem")
        };
    }

    public static MountableFile getLdapDataFile() {
        return MountableFile.forClasspathResource("/ldap/initdata.ldif");
    }

    public static NexusAPI makeApi(final String host, final int port, final String user, final String password) {
        final OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(15, TimeUnit.SECONDS);
        if (user != null && !user.isEmpty()) {
            clientBuilder.addInterceptor(new Interceptor() {
                private final String credentials = Credentials.basic(user, password);
                @Override
                public Response intercept(final Chain chain) throws IOException {
                    final Request request = chain.request();
                    final Request authRequest =
                            request.newBuilder()
                                    .header("Authorization", credentials)
                                    .build();
                    return chain.proceed(authRequest);
                }
            });
        }
        final ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        //mapper.registerModule(new NexusJsonModule());
        final Retrofit retrofit = new Retrofit.Builder()
                .baseUrl("http://" + host + ":" + port + "/service/rest/")
                .addConverterFactory(JacksonConverterFactory.create(mapper))
                .client(clientBuilder.build())
                .build();
        return retrofit.create(NexusAPI.class);
    }

    public static <T> T call(final Call<T> call) throws IOException {
        final retrofit2.Response<T> response = call.execute();
        if (!response.isSuccessful()) {
            final ResponseBody body = response.errorBody();
            Assertions.fail("error from server:\n" + (body != null ? body.string() : "---"));
        }
        return response.body();
    }
}
