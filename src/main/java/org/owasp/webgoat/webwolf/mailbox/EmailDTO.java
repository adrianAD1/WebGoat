package org.owasp.webgoat.webwolf.mailbox;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EmailDTO {

    @NotNull
    @Size(min = 3, max = 100)
    private String recipient;

    @NotNull
    @Size(min = 1, max = 200)
    private String title;

    @NotNull
    @Size(min = 1, max = 5000)
    private String contents;

    @NotNull
    @Size(min = 3, max = 100)
    private String sender;
}
