package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.handlers.ConfigHandler;
import io.github.asharapov.nexus.casc.internal.handlers.Options;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.sonatype.goodies.common.ComponentSupport;
import org.sonatype.nexus.rest.Resource;
import org.sonatype.nexus.rest.WebApplicationMessageException;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * REST API for Sonatype Nexus configuration management.
 *
 * @author Anton Sharapov
 */
@Named
@Singleton
@RequiresAuthentication
@Path("/casc")
public class CascApiResource extends ComponentSupport implements Resource, CascApiResourceDoc {

    private final ConfigHandler configHandler;
    private final Options defaultOptions;
    private final Options extendedOptions;

    @Inject
    public CascApiResource(final ConfigHandler configHandler) {
        this.configHandler = configHandler;
        this.defaultOptions = new Options(null, true, true, false, false);
        this.extendedOptions = new Options(null, true, true, true, true);
    }

    @Override
    @GET
    @Path("config")
    @Produces({"application/yaml", "text/plain"})
    @RequiresAuthentication
    @RequiresPermissions("nexus:*")
    public Response getConfiguration(@QueryParam("showReadOnlyObjects") boolean showReadOnlyObjects) {
        try {
            final Options opts = showReadOnlyObjects ? extendedOptions : defaultOptions;
            final String result = configHandler.load(opts);
            return Response.ok(result, "application/yaml").build();
        } catch (Exception e) {
            throw new WebApplicationMessageException(Response.Status.INTERNAL_SERVER_ERROR, e.getMessage() + "\n" + Utils.stackTrace(e), MediaType.TEXT_PLAIN);
        }
    }

    @POST
    @Path("config")
    @Consumes("text/vnd.yaml")
    @Produces("text/plain")
    @RequiresAuthentication
    @RequiresPermissions("nexus:*")
    public Response applyConfiguration(final String configuration) {
        try {
            final boolean applied = configHandler.store(configuration);
            return Response.status(Response.Status.OK)
                    .entity(applied ? "modified" : "not modified")
                    .build();
        } catch (Exception e) {
            throw new WebApplicationMessageException(Response.Status.INTERNAL_SERVER_ERROR, e.getMessage() + "\n" + Utils.stackTrace(e), MediaType.TEXT_PLAIN);
        }
    }

}
