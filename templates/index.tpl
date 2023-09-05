{include file="header.tpl"}
<div class="panel panel-success">
        {if count($dependency_errors)}
        {foreach from=$dependency_errors key=result item=result_array}
                <p>{$result_array['error']|unescape: "html" nofilter}</p>
        {/foreach}
        {else}
        {if $error != ""}
                <p class="result alert alert-{$result_criticity}">{$error|unescape: "html" nofilter}
                {if $show_extended_error and $extended_error_msg}
                    ({$extended_error_msg})
                {/if}
                </p>
        {/if}
        {include file="$action.tpl"}
        {/if}
</div>
{include file="footer.tpl"}
