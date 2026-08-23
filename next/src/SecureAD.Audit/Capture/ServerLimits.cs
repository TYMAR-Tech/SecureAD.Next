namespace SecureAD.Audit.Capture;

/// <summary>
/// One limit a domain controller enforces on LDAP work, and what capture does about it.
/// </summary>
/// <param name="Name">The limit's name in the controller's own query policy.</param>
/// <param name="DocumentedDefault">
/// The default Microsoft documents, written as it appears there rather than converted, so it can
/// be compared with the article without arithmetic.
/// </param>
/// <param name="WhatItLimits">What the controller does when the limit is reached.</param>
/// <param name="WhatCaptureDoes">
/// The client's side of it. Never "nothing": a limit capture does not respect is a limit capture
/// will meet, and the answer must at least say what happens then.
/// </param>
public sealed record ServerLimit(
    string Name, string DocumentedDefault, string WhatItLimits, string WhatCaptureDoes);

/// <summary>
/// The limits a domain controller places on LDAP work, named rather than guessed.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row B7, and <c>docs/audit/limits-and-failures.md</c> is the document bound to it.
/// Every value here is the documented default from
/// <see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil">View
/// and set LDAP policy in Active Directory by using Ntdsutil.exe</see>. They are <i>defaults</i>:
/// an administrator may change any of them, and a forest that has raised or lowered one is not
/// misbehaving. Capture treats them as the smallest thing it may assume, never as a promise.
/// </para>
/// <para>
/// <b>Why a table of the server's limits, and no limit of the product's own.</b> A client-side
/// requests-per-second budget would be measuring the wrong thing. What a controller spends on a
/// capture is objects read, temporary-table pressure and bytes serialised, none of which is
/// proportional to how many requests were sent: one request is a page of up to a thousand objects,
/// so a rate expressed in requests can be met exactly while the load varies by an order of
/// magnitude. A setting that reads as a lever over production impact and is not one is worse than
/// no setting, because an operator will believe it.
/// </para>
/// <para>
/// What replaces it is not a smaller number. It is a constraint - <b>requests are never
/// pipelined</b> - held by a build guard rather than by a value in a settings file, because the
/// thing that actually protects a customer's controller is that only one request from this product
/// is ever in flight against it.
/// </para>
/// <para>
/// <b>This type is a table compiled into the assembly.</b> It reads nothing and cannot fail. It
/// exposes each limit as its own named member rather than a list, so it needs no exemption from
/// gate 4: there is no collection here that could be empty for two different reasons.
/// </para>
/// </remarks>
public static class ServerLimits
{
    /// <summary>
    /// The page size capture asks for: the documented default of <c>MaxPageSize</c>.
    /// </summary>
    /// <remarks>
    /// Asking for more is pointless - a controller returns at most its own limit whatever the
    /// client requests - and asking for less multiplies round trips over the same object count.
    /// A controller configured lower simply returns smaller pages, which the paging loop handles
    /// without knowing it happened.
    /// </remarks>
    public const int PageSize = 1000;

    /// <summary>
    /// The time limit capture puts on a single search: the documented default of
    /// <c>MaxQueryDuration</c>.
    /// </summary>
    /// <remarks>
    /// Stated by the client so that the bound is visible in the request rather than being whatever
    /// the server happens to impose. Under paging each page is a separate search, so this bounds a
    /// page and not a partition.
    /// </remarks>
    public static TimeSpan QueryDuration { get; } = TimeSpan.FromSeconds(120);

    /// <summary>How many objects come back in one page.</summary>
    public static ServerLimit MaxPageSize { get; } = new(
        "MaxPageSize",
        "1,000 objects",
        "The most objects returned in a single search result. A search whose result may exceed it "
        + "must use the paged results control.",
        "Capture pages every search and asks for exactly this many per page. It never issues an "
        + "unpaged subtree search.");

    /// <summary>How long one search may run.</summary>
    public static ServerLimit MaxQueryDuration { get; } = new(
        "MaxQueryDuration",
        "120 seconds",
        "The most time a controller spends on a single search before returning "
        + "timeLimitExceeded. Searches needing longer must use the paged results control.",
        "Capture sets the same limit on the request. Because every search is paged, the limit "
        + "applies to one page rather than to a partition, so a large partition does not need a "
        + "raised limit - Microsoft advises against raising it.");

    /// <summary>How many values of one attribute come back on one object.</summary>
    public static ServerLimit MaxValRange { get; } = new(
        "MaxValRange",
        "1,500 values",
        "The most values returned for one attribute of one object. Beyond it the values do not "
        + "come back under the name they were asked for, and must be fetched a block at a time "
        + "with a range specifier.",
        "Capture range-retrieves every multi-valued attribute in the catalogue - inventory row B8. "
        + "This is the limit that matters most to correctness rather than to load: an entry that "
        + "silently omits an over-large attribute makes a ten-thousand-member group read as a "
        + "group with no members at all.");

    /// <summary>How long a connection may sit silent before the controller closes it.</summary>
    public static ServerLimit MaxConnIdleTime { get; } = new(
        "MaxConnIdleTime",
        "900 seconds",
        "The longest a client may be idle before the controller closes the connection and returns "
        + "an LDAP disconnect notification.",
        "Capture does not deliberately hold an idle connection: a unit's connection is opened, "
        + "paged through without pause, and closed. The gap between two pages is one write to the "
        + "bundle, and no page can take longer than MaxQueryDuration. If a connection is closed "
        + "anyway, the next request fails - and a failed request is never read as the end of the "
        + "results, which is the whole point of recording this limit.");

    /// <summary>How much paged-search state the controller keeps, in total.</summary>
    public static ServerLimit MaxResultSetSize { get; } = new(
        "MaxResultSetSize",
        "262,144 bytes",
        "The total intermediate data a controller keeps between the searches making up a paged "
        + "result. When it fills, the controller discards the oldest of these intermediate "
        + "results.",
        "This is a per-controller budget, not a per-search one, so it is only at risk when several "
        + "paged searches run against one controller at once. Capture never does that, which is "
        + "one of the reasons the serialisation constraint is load-bearing rather than tidy - "
        + "finding F-S7-12.");

    /// <summary>How many threads a controller gives LDAP work.</summary>
    public static ServerLimit MaxPoolThreads { get; } = new(
        "MaxPoolThreads",
        "4 threads per processor",
        "The most threads per processor a controller dedicates to network input and output, and "
        + "the most that can work on LDAP requests at the same time.",
        "Capture places one request at a time on one controller, so it occupies at most one of "
        + "these. It is recorded because it is the ceiling any future fan-out would be spending - "
        + "inventory row B5.");

    /// <summary>How many connections a controller accepts at once.</summary>
    public static ServerLimit MaxConnections { get; } = new(
        "MaxConnections",
        "5,000 connections",
        "The most simultaneous LDAP connections a controller accepts. Past it, the controller "
        + "drops another connection.",
        "Capture holds one connection per unit and one unit is read at a time, so it holds one. "
        + "Recorded so that a later design holding a connection per unit for the length of a run "
        + "can see what it would be spending.");

    /// <summary>How long a controller waits for a new connection's first request.</summary>
    public static ServerLimit InitRecvTimeout { get; } = new(
        "InitRecvTimeout",
        "120 seconds",
        "The longest a controller waits for a client to send its first request after the "
        + "connection is accepted, before disconnecting it.",
        "Capture binds and searches immediately after connecting. This limit is recorded because "
        + "it forbids a design that opens every unit's connection at the start of a run and uses "
        + "them later.");

    /// <summary>How large a controller's working table for one query may get.</summary>
    public static ServerLimit MaxTempTableSize { get; } = new(
        "MaxTempTableSize",
        "10,000 records",
        "How large the temporary table used to sort and select intermediate results may grow. "
        + "Past it the controller falls back to a much less efficient scan of the whole database.",
        "This is where the cost of a badly shaped filter actually lands, and it is why capture's "
        + "filter is the cheapest one that can express what it needs. Capture requests no sort "
        + "control for the same reason.");

    /// <summary>How many outstanding change notifications one connection may hold.</summary>
    public static ServerLimit MaxNotificationPerConnection { get; } = new(
        "MaxNotificationPerConnection",
        "5 requests",
        "The most outstanding notification requests permitted on one connection, past which the "
        + "controller returns busy to further notification searches.",
        "Capture registers none. A run is a photograph of a forest at one moment, so there is "
        + "nothing for a change notification to be for.");

    /// <summary>The concurrency limit that is no longer enforced.</summary>
    public static ServerLimit MaxActiveQueries { get; } = new(
        "MaxActiveQueries",
        "20 searches, and not enforced",
        "It once bounded concurrent searches on a controller and returned busy past it. Microsoft "
        + "records that it has not been enforced since Windows Server 2003 and does not appear in "
        + "that version's tooling.",
        "Nothing. It is listed so that it is not cited: a limit that looks like a safety margin "
        + "and is not enforced is the kind of thing a later session leans a concurrency decision "
        + "on. The real constraint on concurrency is MaxResultSetSize.");
}
