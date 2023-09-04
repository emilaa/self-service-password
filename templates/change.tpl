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
          <div class="design">
        <div class="pill-1 rotate-45"></div>
        <div class="pill-2 rotate-45"></div>
        <div class="pill-3 rotate-45"></div>
        <div class="pill-4 rotate-45"></div>
      </div>
      <form action="#" method="post" class="form-horizontal">
        <h3 class="title">Change Password</h3>
                <div class="input-groupp">
                    <i class="ri-user-fill"></i>
                    <input type="text" name="login" id="login" value="{$login}" placeholder="İstifadəçi adı" />
                </div>
                <div class="input-groupp">
                    <i class="ri-key-fill"></i>
                    <input type="password" autocomplete="current-password" name="oldpassword" id="oldpassword" placeholder="Mövcud şifrə" />
                </div>
                <div class="input-groupp">
                    <i class="ri-lock-fill"></i>
                    <input type="password" autocomplete="new-password" name="newpassword" id="newpassword" placeholder="Yeni şifrə" />
                </div>
                <div class="input-groupp">
                    <i class="ri-lock-fill"></i>
                    <input type="password" autocomplete="new-password" name="confirmpassword" id="confirmpassword" placeholder="Şifrəni təsdiqlə" />
                </div>
        {if ($use_captcha)}
             {include file="captcha.tpl"}
        {/if}
                <button type="submit" class="login-btn btn btn-success">
                    Təsdiqlə
                </button>
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
