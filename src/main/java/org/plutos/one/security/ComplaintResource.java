package org.plutos.one.security;

import org.plutos.one.util.DigitalSignerDecryptor;
import org.plutos.one.util.DigitalSignerEncryptor;

import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("ibmb")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ComplaintResource {

    @Inject
    DigitalSignerDecryptor digitalSignerDecryptor;

    @Inject
    DigitalSignerEncryptor digitalSignerEncryptor;

    @POST
    @Path("encrypt")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<Response> encryptTest(String payload) throws Exception {
        return Uni.createFrom().item(payload)
                .flatMap(json -> digitalSignerEncryptor.encrypt(json))
                .onItem().transform(encryptedJson -> Response.ok()
                        .entity(encryptedJson)
                        .build());
    }

    @POST
    @Path("decrypt")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<Response> encryptTest(EncryptedResponse encryptedResponse) throws Exception {
        return Uni.createFrom().item(encryptedResponse)
                .flatMap(json -> digitalSignerDecryptor.decrypt(encryptedResponse))
                .onItem().transform(encryptedJson -> Response.ok()
                        .entity(encryptedJson)
                        .build());
    }
}