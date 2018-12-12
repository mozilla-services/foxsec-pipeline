package com.mozilla.secops.alert;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;

public class TemplateManager {
  Configuration cfg;

  public String createEmailBody(String templateName, HashMap<String, Object> variables)
      throws Exception {
    Template temp = cfg.getTemplate(templateName);
    Writer out = new StringWriter();
    temp.process(variables, out);
    return out.toString();
  }

  public TemplateManager(String templatesPath) throws IOException {
    cfg = new Configuration(Configuration.VERSION_2_3_28);
    cfg.setDefaultEncoding("UTF-8");
    cfg.setLogTemplateExceptions(false);
    cfg.setWrapUncheckedExceptions(true);
    cfg.setDirectoryForTemplateLoading(new File(templatesPath));
    cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
  }
}
