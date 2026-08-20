namespace SecureAD.Kernel.Capture;

/// <summary>
/// How an attribute's value arrives from the directory, and therefore how it must be read.
/// </summary>
/// <remarks>
/// A value that is bytes and is read as a string is not a conversion error that shows up as an
/// exception; it is a mangled string that looks like data. <c>objectSid</c> and <c>objectGUID</c>
/// are the obvious cases, and <c>msDS-AllowedToActOnBehalfOfOtherIdentity</c> and
/// <c>msDS-GroupMSAMembership</c> are the dangerous ones, because both are security descriptors and
/// both decide who can take an identity over.
/// </remarks>
public enum AttributeStorage
{
    /// <summary>A directory string. Read as text.</summary>
    Text,

    /// <summary>An octet string. Read as bytes, and never round-tripped through a string.</summary>
    Binary,
}
