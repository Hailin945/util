package com.hl.valid;

import java.util.regex.Pattern;

/**
 * 信息验证工具
 *
 * @author Hailin
 * @date 2019-04-16
 */
public class InfoValidateUtils {

    /**
     * 正则表达式：验证用户名
     */
    private static final String REGEX_USERNAME = "^[a-zA-Z]\\w{5,20}$";

    /**
     * 正则表达式：验证密码
     */
    private static final String REGEX_PASSWORD = "^[a-zA-Z0-9]{6,20}$";

    /**
     * 正则表达式：验证手机号
     */
    private static final String REGEX_MOBILE = "^1\\d{10}$";

    /**
     * 正则表达式：验证邮箱
     */
    private static final String REGEX_EMAIL = "^([a-z0-9A-Z]+[-|\\.]?)+[a-z0-9A-Z]@([a-z0-9A-Z]+(-[a-z0-9A-Z]+)?\\.)+[a-zA-Z]{2,}$";

    /**
     * 正则表达式：验证所有字符都是汉字
     */
    private static final String REGEX_CHINESE = "^[\\u4e00-\\u9fa5]{0,}$";

    /**
     * 正则表达式：验证以字母开头
     */
    private static final String REGEX_LETTER_START = "^[a-zA-Z][\\s\\S]*$";

    /**
     * 正则表达式：验证身份证（15位或者18位，最后一位可以为字母）
     * 假设18位身份证号码:41000119910101123X  410001 19910101 123X
     * ^开头
     * [1-9] 第一位1-9中的一个             4
     * \\d{5} 五位数字                    10001（前六位省市县地区）
     * (18|19|20)                       19（现阶段可能取值范围18xx-20xx年）
     * \\d{2}                           91（年份）
     * ((0[1-9])|(10|11|12))            01（月份）
     * (([0-2][1-9])|10|20|30|31)       01（日期）
     * \\d{3} 三位数字                   123（第十七位奇数代表男，偶数代表女）
     * [0-9Xx] 0123456789Xx其中的一个    X（第十八位为校验值,小写x是为了用户输入时容错）
     * $结尾
     * 假设15位身份证号码:410001910101123  410001 910101 123
     * ^开头
     * [1-9] 第一位1-9中的一个            4
     * \\d{5} 五位数字                   10001（前六位省市县地区）
     * \\d{2}                           91（年份）
     * ((0[1-9])|(10|11|12))            01（月份）
     * (([0-2][1-9])|10|20|30|31)       01（日期）
     * \\d{3} 三位数字                   123（第十五位奇数代表男，偶数代表女），15位身份证不含X
     * $结尾
     */
    private static final String REGEX_ID_NUMBER = "(^[1-9]\\d{5}(18|19|20)\\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\\d{3}[0-9Xx]$)|" +
            "(^[1-9]\\d{5}\\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\\d{3}$)";

    /**
     * 正则表达式：验证URL
     */
    private static final String REGEX_URL = "http(s)?://([\\w-]+\\.)+[\\w-]+(/[\\w- ./?%&=]*)?";

    /**
     * 正则表达式：验证IP地址
     */
    private static final String REGEX_IP_ADDR = "(25[0-5]|2[0-4]\\d|[0-1]\\d{2}|[1-9]?\\d)";

    /**
     * 正则表达式：验证驾校编号
     */
    private static final String REGEX_SCHOOL_CODE = "^\\d{3}";

    /**
     * 正则表达式：验证车牌号
     */
    private static final String REGEX_LICENSE_PLATE_NUMBER = "^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领A-Z]{1}[A-Z]{1}[A-Z0-9]{4}[A-Z0-9挂学警港澳]{1}$";

    /**
     * 校验用户名
     *
     * @param username 用户名
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isUsername(final String username) {
        return Pattern.matches(REGEX_USERNAME, username);
    }

    /**
     * 校验密码
     *
     * @param password 密码
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isPassword(final String password) {
        return Pattern.matches(REGEX_PASSWORD, password);
    }

    /**
     * 校验手机号
     *
     * @param mobile 手机号
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isMobile(final String mobile) {
        return Pattern.matches(REGEX_MOBILE, mobile);
    }

    /**
     * 校验邮箱
     *
     * @param email 邮箱
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isEmail(final String email) {
        return Pattern.matches(REGEX_EMAIL, email);
    }

    /**
     * 校验汉字
     *
     * @param chinese 中文汉字
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isChinese(final String chinese) {
        if (chinese == null || "".equals(chinese)) {
            return false;
        }
        return Pattern.matches(REGEX_CHINESE, chinese);
    }

    /**
     * 校验身份证
     *
     * @param idNumber 身份证号
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isIdNumber(final String idNumber) {
        if (null == idNumber || "".equals(idNumber)) {
            return false;
        }
        boolean matches = idNumber.matches(REGEX_ID_NUMBER);
        // 判断第18位校验值
        if (matches) {
            if (idNumber.length() == 18) {
                try {
                    char[] charArray = idNumber.toCharArray();
                    // 前十七位加权因子
                    int[] idCardWi = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
                    // 这是除以11后，可能产生的11位余数对应的验证码
                    String[] idCardY = {"1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"};
                    int sum = 0;
                    for (int i = 0; i < idCardWi.length; i++) {
                        int current = Integer.parseInt(String.valueOf(charArray[i]));
                        int count = current * idCardWi[i];
                        sum += count;
                    }
                    char idCardLast = charArray[17];
                    int idCardMod = sum % 11;
                    if (idCardY[idCardMod].toUpperCase().equals(String.valueOf(idCardLast).toUpperCase())) {
                        return true;
                    } else {
                        /// 正式使用中注释掉以下调试信息
                        // System.out.println("身份证最后一位:" + String.valueOf(idCardLast).toUpperCase() +
                        //         "错误,正确的应该是:" + idCardY[idCardMod].toUpperCase());
                        return false;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    /// 正式使用中注释掉以下调试信息
                    // System.out.println("异常:" + idNumber);
                    return false;
                }
            }
        }
        return matches;
    }

    /**
     * 校验URL
     *
     * @param url URL
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isUrl(final String url) {
        return Pattern.matches(REGEX_URL, url);
    }

    /**
     * 校验IP地址
     *
     * @param ipAddr IP
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isIPAddr(final String ipAddr) {
        return Pattern.matches(REGEX_IP_ADDR, ipAddr);
    }

    /**
     * 校验驾校编号
     *
     * @param schoolCode 驾校编号
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isSchoolCode(final String schoolCode) {
        return Pattern.matches(REGEX_SCHOOL_CODE, schoolCode);
    }

    /**
     * 验证车牌号
     *
     * @param licensePlateNumber 车牌号
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isLicensePlatNumber(final String licensePlateNumber) {
        return Pattern.matches(REGEX_LICENSE_PLATE_NUMBER, licensePlateNumber);
    }

    /**
     * 验证字符串以字母开头
     *
     * @param s 需要验证的字符串
     * @return 校验通过返回true，否则返回false
     */
    public static boolean isLetterStart(final String s) {
        return Pattern.matches(REGEX_LETTER_START, s);
    }
}
