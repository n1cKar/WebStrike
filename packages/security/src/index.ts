export * from "./constants";
export * from "./ip";
export * from "./scope";
export * from "./ssrf";
export * from "./http";
export * from "./analysis";

/**
 * WebStrike security core.
 *
 * Everything a request needs to cross the network goes through this package:
 * scope validation -> DNS/SSRF allowlisting -> redirect revalidation. It is
 * intentionally free of framework dependencies so it can be unit-tested in
 * isolation and reused on any host.
 */