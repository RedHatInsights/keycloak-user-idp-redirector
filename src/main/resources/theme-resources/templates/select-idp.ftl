<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        Select Identity Provider
    <#elseif section = "form">
        <div id="kc-select-idp-form">
            <form action="${url.loginAction}" method="post">
                <input type="hidden" name="credentialId" value=""/>
                <#list idps as idp>
                    <div class="${properties.kcFormGroupClass!}">
                        <button type="submit"
                                name="idpAlias"
                                value="${idp.alias}"
                                class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!} ${properties.kcButtonBlockClass!}">
                            ${(idp.displayName?has_content)?then(idp.displayName, idp.alias)}
                        </button>
                    </div>
                </#list>
            </form>
        </div>
    </#if>
</@layout.registrationLayout>
