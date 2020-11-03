using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace xml_signature_provider
{
    public class DSS : AsymmetricAlgorithm
    {
    }

    public class DssSignatureFormatter : AsymmetricSignatureFormatter
    {

        public DSS Key { get; set; }
        public HashAlgorithm HashAlgorithm { get; set; }

        public DssSignatureFormatter(DSS key)
        {
            Key = key;
        }

        public override byte[] CreateSignature(byte[] rgbHash)
        {
            return new byte[2048];
        }

        public override void SetHashAlgorithm(string strName)
        {
            switch (strName)
            {
                case "SHA256":
                    HashAlgorithm = SHA256.Create();
                    break;
                default:
                    throw new ArgumentException("Unknown hash algorithm name", nameof(strName));
            }
        }

        public override void SetKey(AsymmetricAlgorithm key)
        {
            throw new NotImplementedException();
        }
    }

    public class DSSSignatureDescription : SignatureDescription
    {
        public DSSSignatureDescription()
        {
            KeyAlgorithm = typeof(DSS).FullName;
            DigestAlgorithm = typeof(SHA256Managed).FullName;
            FormatterAlgorithm = typeof(DssSignatureFormatter).FullName;
            //DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
        }

        public DSSSignatureDescription(SecurityElement el) : base(el)
        {
            KeyAlgorithm = typeof(DSS).FullName;
            DigestAlgorithm = typeof(SHA256Managed).FullName;
            FormatterAlgorithm = typeof(DssSignatureFormatter).FullName;
            //DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            return base.CreateDeformatter(key);
        }

        public override HashAlgorithm CreateDigest()
        {
            return SHA256.Create();
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key is DSS dssKey)
            {
                return new DssSignatureFormatter(dssKey);
            }
            throw new ArgumentException("Argument is not DSS asymmetric algorithm", nameof(key));
        }
    }

    class Program
    {

        public static SignedXml Extended(XmlDocument doc)
        {
            var signatureMethod = @"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            CryptoConfig.AddAlgorithm(typeof(DSSSignatureDescription), signatureMethod);

            var signedXml = new SignedXml(doc)
            {
                SigningKey = new DSS(),
            };

            signedXml.SignedInfo.SignatureMethod = signatureMethod;

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();

            return signedXml;
        }

        public static SignedXml Extended2(XmlDocument doc)
        {
            var signatureMethod = @"http://www.w3.org/2001/04/xmldsig-more#non-standard";
            CryptoConfig.AddAlgorithm(typeof(DSSSignatureDescription), signatureMethod);

            var signedXml = new SignedXml(doc)
            {
                SigningKey = new DSS(),
            };

            signedXml.SignedInfo.SignatureMethod = signatureMethod;

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();

            return signedXml;
        }


        public static SignedXml Standard(XmlDocument doc)
        {
            var signedXml = new SignedXml(doc)
            {
                SigningKey = RSA.Create(2048),
            };

            var signatureMethod = @"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            signedXml.SignedInfo.SignatureMethod = signatureMethod;

            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();

            return signedXml;
        }

        static void Main(string[] args)
        {
            var xmlStream = new MemoryStream(Encoding.UTF8.GetBytes("<root><child/></root>"));
            var doc = new XmlDocument();
            doc.Load(xmlStream);

            //var signedXml = Standard(doc);
            //var signedXml = Extended(doc);
            var signedXml = Extended2(doc);

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            // Save the signed XML document to a file specified
            // using the passed string.

            XmlTextWriter xmltw = new XmlTextWriter(Console.OpenStandardOutput(), new UTF8Encoding(false));
            doc.WriteTo(xmltw);
            xmltw.Close();
        }
    }
}
