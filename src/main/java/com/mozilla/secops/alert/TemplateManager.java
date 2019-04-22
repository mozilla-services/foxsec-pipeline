package com.mozilla.secops.alert;

import com.mozilla.secops.GcsUtil;
import freemarker.cache.ByteArrayTemplateLoader;
import freemarker.cache.ClassTemplateLoader;
import freemarker.cache.MultiTemplateLoader;
import freemarker.cache.TemplateLoader;
import freemarker.template.Configuration;
import freemarker.template.MalformedTemplateNameException;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.TemplateNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;

/** Manager class for processing templates using Freemarker */
public class TemplateManager {
  private Configuration cfg;
  private final AlertConfiguration alertCfg;
  private ArrayList<String> registeredTemplates;

  /**
   * Create processed template using supplied template name and template variables
   *
   * @param templateName Name of template file
   * @param variables Variables for template
   * @return Assembled template
   */
  public String processTemplate(String templateName, HashMap<String, Object> variables)
      throws IOException, MalformedTemplateNameException, TemplateException,
          TemplateNotFoundException {
    Template temp = cfg.getTemplate(templateName);
    Writer out = new StringWriter();
    temp.process(variables, out);
    return out.toString();
  }

  /** Validate TemplateManager by checking that all registered templates can be found. */
  public void validate()
      throws TemplateNotFoundException, MalformedTemplateNameException, IOException {
    if (registeredTemplates == null) {
      return;
    }
    for (String tmpl : registeredTemplates) {
      Template temp = cfg.getTemplate(tmpl);
    }
  }

  private ByteArrayTemplateLoader loadTemplatesFromGCS(String basePath) {
    ByteArrayTemplateLoader baTemplateLoader = new ByteArrayTemplateLoader();
    for (String tmpl : registeredTemplates) {
      byte[] templateContents = GcsUtil.fetchContent(String.format("%s%s", basePath, tmpl));
      // If we don't find the template, we just don't set it. This is done so that the
      // ClassTemplateLoader has a chance to try and find the template if it's not in GCS.
      if (templateContents != null) {
        baTemplateLoader.putTemplate(tmpl, templateContents);
      }
    }
    return baTemplateLoader;
  };

  /** Construct new template manager object */
  public TemplateManager(AlertConfiguration alertCfg) {
    this.alertCfg = alertCfg;
    registeredTemplates = alertCfg.getRegisteredTemplates();
    cfg = new Configuration(Configuration.VERSION_2_3_28);
    cfg.setDefaultEncoding("UTF-8");
    cfg.setLogTemplateExceptions(false);
    cfg.setWrapUncheckedExceptions(true);
    cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

    ClassTemplateLoader ctl = new ClassTemplateLoader(TemplateManager.class, "/alert/templates");
    if (alertCfg.getGcsTemplateBasePath() != null) {
      ByteArrayTemplateLoader stl = loadTemplatesFromGCS(alertCfg.getGcsTemplateBasePath());
      MultiTemplateLoader mtl = new MultiTemplateLoader(new TemplateLoader[] {stl, ctl});
      cfg.setTemplateLoader(mtl);
    } else {
      cfg.setTemplateLoader(ctl);
    }
  }
}
