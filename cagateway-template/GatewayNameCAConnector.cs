using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CAProxy.AnyGateway.Models.Configuration;
using CAProxy.Common;

using CSS.PKI;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using GatewayNameConstants = Keyfactor.Extensions.AnyGateway.Company.Product.Constants;

namespace Keyfactor.Extensions.AnyGateway.Company.Product
{
	public class GatewayNameCAConnector : BaseCAConnector, ICAConnectorConfigInfoProvider
	{
		#region Fields and Constructors

		/// <summary>
		/// Provides configuration information for the <see cref="GatewayNameCAConnector"/>
		/// </summary>
		private ICAConnectorConfigProvider ConfigProvider { get; set; }

		//Define any additional private fields here

		#endregion Fields and Constructors

		#region ICAConnector Methods

		/// <summary>
		/// Initialize the <see cref="GatewayNameCAConnector"/>
		/// </summary>
		/// <param name="configProvider">The config provider contains information required to connect to the CA.</param>
		public override void Initialize(ICAConnectorConfigProvider configProvider)
		{
			ConfigProvider = configProvider;
		}

		/// <summary>
		/// Enrolls for a certificate through the API.
		/// </summary>
		/// <param name="certificateDataReader">Reads certificate data from the database.</param>
		/// <param name="csr">The certificate request CSR in PEM format.</param>
		/// <param name="subject">The subject of the certificate request.</param>
		/// <param name="san">Any SANs added to the request.</param>
		/// <param name="productInfo">Information about the CA product type.</param>
		/// <param name="requestFormat">The format of the request.</param>
		/// <param name="enrollmentType">The type of the enrollment, i.e. new, renew, or reissue.</param>
		/// <returns></returns>
		public override EnrollmentResult Enroll(ICertificateDataReader certificateDataReader, string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Returns a single certificate record by its serial number.
		/// </summary>
		/// <param name="caRequestID">The CA request ID for the certificate.</param>
		/// <returns></returns>
		public override CAConnectorCertificate GetSingleRecord(string caRequestID)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Attempts to reach the CA over the network.
		/// </summary>
		public override void Ping()
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Revokes a certificate by its serial number.
		/// </summary>
		/// <param name="caRequestID">The CA request ID.</param>
		/// <param name="hexSerialNumber">The hex-encoded serial number.</param>
		/// <param name="revocationReason">The revocation reason.</param>
		/// <returns></returns>
		public override int Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Synchronizes the gateway with the external CA
		/// </summary>
		/// <param name="certificateDataReader">Provides information about the gateway's certificate database.</param>
		/// <param name="blockingBuffer">Buffer into which certificates are places from the CA.</param>
		/// <param name="certificateAuthoritySyncInfo">Information about the last CA sync.</param>
		/// <param name="cancelToken">The cancellation token.</param>
		public override void Synchronize(ICertificateDataReader certificateDataReader, BlockingCollection<CAConnectorCertificate> blockingBuffer, CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Validates that the CA connection info is correct.
		/// </summary>
		/// <param name="connectionInfo">The information used to connect to the CA.</param>
		public override void ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Validates that the product information for the CA is correct
		/// </summary>
		/// <param name="productInfo">The product information.</param>
		/// <param name="connectionInfo">The CA connection information.</param>
		public override void ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
		{
			throw new NotImplementedException();
		}

		[Obsolete]
		public override EnrollmentResult Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
		{
			throw new NotImplementedException();
		}

		[Obsolete]
		public override void Synchronize(ICertificateDataReader certificateDataReader, BlockingCollection<CertificateRecord> blockingBuffer, CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken, string logicalName)
		{
			throw new NotImplementedException();
		}

		#endregion ICAConnector Methods

		#region ICAConnectorConfigInfoProvider Methods

		/// <summary>
		/// Returns the default CA connector section of the config file.
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, object> GetDefaultCAConnectorConfig()
		{
			return new Dictionary<string, object>()
			{
			};
		}

		/// <summary>
		/// Gets the default comment on the default product type.
		/// </summary>
		/// <returns></returns>
		public string GetProductIDComment()
		{
			return "";
		}

		/// <summary>
		/// Gets annotations for the CA connector properties.
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
		{
			return new Dictionary<string, PropertyConfigInfo>();
		}

		/// <summary>
		/// Gets annotations for the template mapping parameters
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Gets default template map parameters for GlobalSign Atlas product types.
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, string> GetDefaultTemplateParametersConfig()
		{
			throw new NotImplementedException();
		}

		#endregion ICAConnectorConfigInfoProvider Methods

		#region Helper Methods

		// All private helper methods go here

		#endregion Helper Methods
	}
}