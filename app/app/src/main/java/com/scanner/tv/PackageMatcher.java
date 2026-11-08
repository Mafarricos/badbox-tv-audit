package com.scanner.tv;

import java.util.HashSet;
import java.util.Set;

/**
 * Motor de correspondência exata de nomes de pacotes de IoCs (JT-05, IOC-02).
 * Compara pacotes de forma exata e case-insensitive, prevenindo falsos positivos por correspondência de substring.
 */
public class PackageMatcher {

    private final Set<String> mIocPackages = new HashSet<>();

    public PackageMatcher(Iterable<String> iocs) {
        if (iocs != null) {
            for (String ioc : iocs) {
                if (ioc != null && !ioc.trim().isEmpty()) {
                    mIocPackages.add(ioc.trim().toLowerCase());
                }
            }
        }
    }

    public boolean matches(String packageName) {
        if (packageName == null || packageName.trim().isEmpty()) {
            return false;
        }
        return mIocPackages.contains(packageName.trim().toLowerCase());
    }
}
