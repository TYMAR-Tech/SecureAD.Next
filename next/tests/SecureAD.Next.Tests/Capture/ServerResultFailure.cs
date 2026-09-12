using System.DirectoryServices.Protocols;
using System.Reflection;
using Xunit;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// Builds the exception the platform's LDAP client raises when a controller answers a request with
/// a result code that is not success.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this has to exist at all.</b> <c>LdapConnection.EndSendRequest</c> does not raise an
/// <see cref="LdapException"/> for a non-success server result. It raises a
/// <see cref="DirectoryOperationException"/> carrying the answer on its <c>Response</c>, and that
/// type does not derive from <see cref="LdapException"/>. Every test that modelled a busy
/// controller by throwing an <see cref="LdapException"/> was therefore modelling something the
/// product will never see from a real one - which is how a retry that never ran looked covered.
/// </para>
/// <para>
/// <b>Why it uses reflection, which is not a thing to do lightly.</b> Every
/// <see cref="DirectoryResponse"/> in <c>System.DirectoryServices.Protocols</c> has internal
/// constructors only, so there is no supported way to build one. The choice is between reaching
/// for the real type and testing against an invented stand-in, and an invented stand-in is what
/// produced the gap in the first place.
/// </para>
/// <para>
/// <b>It fails rather than skips if the shape changes.</b> A missing constructor means Microsoft
/// has altered how a server result arrives, which is exactly the moment
/// <c>RetryPolicy.FailureFor</c> needs rechecking - so the assertion is inside, and a silent skip
/// is not available.
/// </para>
/// </remarks>
internal static class ServerResultFailure
{
    /// <summary>
    /// The exception a controller's non-success answer arrives as.
    /// </summary>
    /// <param name="code">The result code the controller returned.</param>
    /// <param name="message">The controller's own message.</param>
    public static DirectoryOperationException AnsweredWith(ResultCode code, string message)
    {
        var constructor = typeof(SearchResponse).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance,
            binder: null,
            [
                typeof(string),
                typeof(DirectoryControl[]),
                typeof(ResultCode),
                typeof(string),
                typeof(Uri[]),
            ],
            modifiers: null);

        Assert.True(
            constructor is not null,
            "SearchResponse no longer has the internal constructor these tests build a server "
            + "answer with. This is not a reason to skip them. The point of this helper is that "
            + "the shape of a non-success server result belongs to Microsoft rather than to this "
            + "product, so a change to it means RetryPolicy.FailureFor must be rechecked against "
            + "the new shape before a capture is trusted against a customer's forest.");

        var response = (SearchResponse)constructor!.Invoke(
            [null, null, code, message, null]);

        return new DirectoryOperationException(response, message);
    }
}
