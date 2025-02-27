package org.owasp.webgoat.lessons.deserialization;

import java.io.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

// Clase para restringir la deserialización solo a clases permitidas
class SecureObjectInputStream extends ObjectInputStream {
    
    private static final List<String> ALLOWED_CLASSES = Arrays.asList(
        "org.safe.AllowedClass1",
        "org.safe.AllowedClass2"
    );

    public SecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(osc.getName())) {
            throw new InvalidClassException("Intento de deserialización no autorizada", osc.getName());
        }
        return super.resolveClass(osc);
    }
}

// Controlador para manejar la entrada de datos y evitar deserialización insegura
@RestController
@AssignmentHints({
  "insecure-deserialization.hints.1",
  "insecure-deserialization.hints.2",
  "insecure-deserialization.hints.3"
})
public class InsecureDeserializationTask extends AssignmentEndpoint {

    @PostMapping("/InsecureDeserialization/task")
    @ResponseBody
    public AttackResult completed(@RequestParam String token) throws IOException {
        String b64token;
        long before;
        long after;
        int delay;

        // Reemplazar caracteres especiales para una codificación válida
        b64token = token.replace('-', '+').replace('_', '/');

        try (SecureObjectInputStream ois =
             new SecureObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {
            before = System.currentTimeMillis();
            Object o = ois.readObject();

            // Validar que el objeto deserializado sea de un tipo esperado
            if (!(o instanceof VulnerableTaskHolder)) {
                return failed(this).feedback("insecure-deserialization.wrongobject").build();
            }

            after = System.currentTimeMillis();
        } catch (InvalidClassException e) {
            return failed(this).feedback("insecure-deserialization.invalidversion").build();
        } catch (IllegalArgumentException e) {
            return failed(this).feedback("insecure-deserialization.expired").build();
        } catch (Exception e) {
            return failed(this).feedback("insecure-deserialization.invalidversion").build();
        }

        delay = (int) (after - before);
        if (delay > 7000 || delay < 3000) {
            return failed(this).build();
        }

        return success(this).build();
    }
}
