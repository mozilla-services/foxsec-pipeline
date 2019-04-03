package com.mozilla.secops.alert;

import freemarker.template.Configuration;
import freemarker.template.MalformedTemplateNameException;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.TemplateNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;

/** Manager class for generating html email templates using Freemarker */
public class TemplateManager {
  private Configuration cfg;

  /**
   * Create html email body using supplied template name and template variables
   *
   * @param templateName Name of template file
   * @param variables Variables for template
   * @return Assembled email body
   */
  public String createEmailBody(String templateName, HashMap<String, Object> variables)
      throws IOException, MalformedTemplateNameException, TemplateException,
          TemplateNotFoundException {
    Template temp = cfg.getTemplate(templateName);
    Writer out = new StringWriter();
    temp.process(variables, out);
    return out.toString();
  }

  /** Construct new template manager object */
  public TemplateManager() {
    cfg = new Configuration(Configuration.VERSION_2_3_28);
    cfg.setDefaultEncoding("UTF-8");
    cfg.setLogTemplateExceptions(false);
    cfg.setWrapUncheckedExceptions(true);
    cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
    cfg.setClassForTemplateLoading(TemplateManager.class, "/alert/templates/");
  }
}
