/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.deserialization;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.util.Base64;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.*;
import java.util.Arrays;
import java.util.List;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Clase personalizada para restringir la deserialización a clases permitidas
public class SecureObjectInputStream extends ObjectInputStream {

    // Lista de clases permitidas para deserialización
    private static final List<String> APPROVED_CLASSES = Arrays.asList(
        AllowedClass1.class.getName(),
        AllowedClass2.class.getName()
    );

    public SecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {
        if (!APPROVED_CLASSES.contains(osc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization attempt", osc.getName());
        }
        return super.resolveClass(osc);
    }
}

// Clase encargada de procesar las solicitudes HTTP
public class RequestProcessor {

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try (ServletInputStream servletIS = request.getInputStream();
             ObjectInputStream objectIS = new SecureObjectInputStream(servletIS)) {
            
            Object input = objectIS.readObject();

            // Verificar si la clase deserializada es la esperada
            if (!(input instanceof AllowedClass1 || input instanceof AllowedClass2)) {
                throw new SecurityException("Invalid object type received");
            }

            // Aquí puedes procesar el objeto de forma segura
            response.getWriter().write("Object received and validated");
            
        } catch (InvalidClassException e) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Deserialization of this class is not allowed.");
        } catch (ClassNotFoundException | SecurityException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid object type received.");
        }
    }
}
