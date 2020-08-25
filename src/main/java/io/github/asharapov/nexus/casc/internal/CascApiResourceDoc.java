package io.github.asharapov.nexus.casc.internal;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

import javax.ws.rs.core.Response;

/**
 * Swagger documentation for {@link CascApiResource}
 *
 * @author Anton Sharapov
 */
@Api(value = "CASC")
public interface CascApiResourceDoc {

    @ApiOperation("Retrieve current configuration.")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The current configuration is returned."),
            @ApiResponse(code = 401, message = "Unauthorized user."),
            @ApiResponse(code = 403, message = "The user does not have permission to perform the operation."),
            @ApiResponse(code = 500, message = "Execution failed with exception")
    })
    Response getConfiguration(
            @ApiParam(value = "Option for displaying non-modifiable or hidden objects.", required = false) boolean showReadOnlyObjects
    );

    @ApiOperation("Applies new configuration.")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The new configuration was successfully applied on the server."),
            @ApiResponse(code = 401, message = "Unauthorized user."),
            @ApiResponse(code = 403, message = "The user does not have permission to perform the operation."),
            @ApiResponse(code = 500, message = "Execution failed with exception")
    })
    Response applyConfiguration(@ApiParam("New configuration in the yaml format") final String configuration);

}
