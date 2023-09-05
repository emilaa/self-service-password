{include file="header.tpl"}
<div class="panel panel-success">
        {if count($dependency_errors)}
        {foreach from=$dependency_errors key=result item=result_array}
                <p>{$result_array['error']|unescape: "html" nofilter}</p>
        {/foreach}
        {else}

        {include file="$action.tpl"}
        {/if}
</div>
{include file="footer.tpl"}
