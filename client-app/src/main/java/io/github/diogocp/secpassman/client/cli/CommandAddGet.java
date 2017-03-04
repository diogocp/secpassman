package io.github.diogocp.secpassman.client.cli;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;
import java.util.ArrayList;
import java.util.List;

@Parameters()
public class CommandAddGet {

    @Parameter(description = "DOMAIN USERNAME", arity = 2)
    private List<String> domainUsername = new ArrayList<>();

    public String getDomain() {
        return domainUsername.get(0);
    }

    public String getUsername() {
        return domainUsername.get(1);
    }

    public void checkArgs() {
        if (domainUsername.size() < 1) {
            throw new ParameterException("The following parameters are required: DOMAIN USERNAME");
        }
        if (domainUsername.size() == 1) {
            throw new ParameterException("The following parameter is required: USERNAME");
        }
        if (domainUsername.size() > 2) {
            throw new ParameterException("Too many parameters supplied");
        }
    }
}
