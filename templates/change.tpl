{if $prehook_return and $display_prehook_error and $prehook_return > 0}
    <p class="text-danger">{$prehook_output[0]}</p>
{/if}
{if $posthook_return and $display_posthook_error and $posthook_return > 0}
    <p class="text-danger">{$posthook_output[0]}</p>
{/if}
{if $result !== "passwordchanged"}
    {if $pwd_show_policy !== "never" and $pwd_show_policy_pos === 'above'}
        {include file="policy.tpl"}
    {/if}
    <div class="alert alert-info">
      <form action="#" method="post" class="form-horizontal">
                <div class="input-group">
                    <i class="ri-user-fill"></i>
                    <input type="text" name="login" id="login" value="{$login}" placeholder="İstifadəçi adı" />
                </div>
                <div class="input-group">
                    <i class="ri-key-fill"></i>
                    <input type="password" autocomplete="current-password" name="oldpassword" id="oldpassword" placeholder="Mövcud şifrə" />
                </div>
                <div class="input-group">
                    <i class="ri-lock-fill"></i>
                    <input type="password" autocomplete="new-password" name="newpassword" id="newpassword" placeholder="Yeni şifrə" />
                </div>
                <div class="input-group">
                    <i class="ri-lock-fill"></i>
                    <input type="password" autocomplete="new-password" name="confirmpassword" id="confirmpassword" placeholder="Şifrəni təsdiqlə" />
                </div>
        {if ($use_captcha)}
             {include file="captcha.tpl"}
        {/if}
        <div class="form-group">
            <div class="col-sm-offset-4 col-sm-8">
                <button type="submit" class="login-btn btn btn-success">
                    Təsdiqlə
                </button>
            </div>
        </div>
      </form>
    </div>
{if $pwd_show_policy !== "never" and $pwd_show_policy_pos === 'below'}
    {include file="policy.tpl"}
{/if}
{elseif $msg_passwordchangedextramessage}
    <div class="result alert alert-{$result_criticity}">
    <p><i class="fa fa-fw {$result_fa_class}" aria-hidden="true"></i> {$msg_passwordchangedextramessage|unescape: "html" nofilter}</p>
    </div>
{/if}
