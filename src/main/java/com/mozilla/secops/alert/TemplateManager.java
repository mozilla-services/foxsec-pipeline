package com.mozilla.secops.alert;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;

/** Manager class for generating html email templates using Freemarker */
public class TemplateManager {
  Configuration cfg;

  /**
   * Create html email body using supplied template name and template variables
   *
   * @param templateName Name of template file
   * @param variables Variables for template
   * @return Assembled email body
   */
  public String createEmailBody(String templateName, HashMap<String, Object> variables)
      throws Exception {
    Template temp = cfg.getTemplate(templateName);
    Writer out = new StringWriter();
    temp.process(variables, out);
    return out.toString();
  }

  /**
   * Construct new template manager object
   *
   * @param templatesPath Path to Freemarker html templates
   */
  public TemplateManager(String templatesPath) throws IOException {
    cfg = new Configuration(Configuration.VERSION_2_3_28);
    cfg.setDefaultEncoding("UTF-8");
    cfg.setLogTemplateExceptions(false);
    cfg.setWrapUncheckedExceptions(true);
    cfg.setDirectoryForTemplateLoading(new File(templatesPath));
    cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
  }
}
