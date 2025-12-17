package com.security.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.SecretKey;
import java.util.*;

public class KeyGenerator {

    public static void main(String[] args) throws JSONException, JsonProcessingException {

        Map<String, Object> b = new ObjectMapper().readValue("{\"StoreProcedures\":{},\"TABLES\":{\"account_TABLE\":[\"account_id\",\"account_parent\",\"account_description\",\"account_type\",\"account_rollup\",\"Custom_Members\"],\"bloom_TABLE\":[\"Buyer\",\"BuyerEmail\",\"Project_Number\",\"Supplier\",\"Product_Description\",\"Project_Start_Date\",\"Project_End_Date\",\"SME\",\"Category\",\"Appointment_Type\",\"Project_Budget\",\"Proposal_Fee\",\"PO_Value\",\"Invoiced\",\"ACCES_STAGE\",\"ACCES_STAGE_ORDER\",\"id\",\"username\"],\"cashflow_bibirbal_TABLE\":[\"#\",\"Category\",\"Fiscal Year\",\"Date\",\"Amount\",\"Transaction Status\",\"Month\",\"Expense Category\",\"Expenses Amt\",\"Abs Expenses amt\",\"Income\",\"Balance Amount\",\"Customer-Supplier Category\",\"Customer\",\"Month Year\",\"Transaction Type\",\"Property taxes\",\"Rent\",\"Salaries\",\"Utilities\",\"Insurance\",\"Income-Expense Category\"],\"customers_TABLE\":[\"customerNumber\",\"customerName\",\"contactLastName\",\"contactFirstName\",\"phone\",\"addressLine1\",\"addressLine2\",\"city\",\"state\",\"postalCode\",\"country\",\"salesRepEmployeeNumber\",\"creditLimit\",\"countryCode\"],\"customerstates_TABLE\":[\"recordId\",\"state\",\"stateId\"],\"daily_product_sales_TABLE\":[\"SKU\",\"Brand\",\"Product Name\",\"HSN/SAC code\",\"Net Weight\\tContent\",\"Product Packaging\",\"Quantity\",\"Total Cost Price\",\"Average Cost Price\",\"Total Selling Price\",\"Average Selling Price\",\"Total MRP\",\"Average MRP\",\"Profit\",\"Unique Customer Count\",\"Total Orders\",\"Entry Date\"],\"detail_instock_TABLE\":[\"SKU\",\"PRODUCT_NAME\",\"HSN/SAC CODE\",\"SELL AS\",\"PRODUCT_UNIT\",\"NET WEIGHT/CONTENT\",\"MEASUREMENT UNIT\",\"BATCH/LOT_NO_ID\",\"BATCH/LOT_NO\",\"BATCH CREATION DATE\",\"BATCH ORIGIN\",\"OUTLET-ACCOUNT\",\"BARCODE\",\"EXPIRY BY DATE\",\"MANUFACTURING_DATE\",\"BEST_BEFORE\",\"DAYS / MONTHS / YEARS\",\"OUTWARD_STOCK\",\"IN_STOCK_IN_SYSTEM\",\"IN_STOCK_BY_USER\",\"MRP\",\"SELLING_PRICE\",\"SELLING_PRICE_PER_NET_WEIGHT/CONTENT\",\"COST_PRICE\",\"MANUFACTURER\",\"SUPPLIER\",\"TOTAL INSTOCK VALUE\"],\"employees_TABLE\":[\"employeeNumber\",\"lastName\",\"firstName\",\"extension\",\"email\",\"officeCode\",\"reportsTo\",\"jobTitle\"],\"leads_TABLE\":[\"id\",\"first_name\",\"last_name\",\"age\",\"sex\",\"mobile1\",\"mobile2\",\"address\",\"city\",\"state\",\"pincode\",\"model\",\"budget\",\"comments\",\"email\",\"suitable_time\",\"time_frame\",\"probablity\"],\"manufacturing_TABLE\":[\"Sr No\",\"Year\",\"Month\",\"Month_Year\",\"Product\",\"Country\",\"Unit Price\",\"Units\",\"Revenue\",\"Gross Profit\",\"Net Profit\",\"Revenue_Target\",\"Net_Profit_Target%\",\"Net_Profit_Target\",\"Expenses\",\"COGS\",\"Profit Margin\",\"Gross Profit Margin\",\"Expense Category\"],\"offices_TABLE\":[\"officeCode\",\"city\",\"phone\",\"addressLine1\",\"addressLine2\",\"state\",\"country\",\"postalCode\",\"territory\",\"countryCode\"],\"order_details_TABLE\":[\"id\",\"ordernumber\",\"productcode\",\"quatity_ordered\"],\"orderdetails_TABLE\":[\"orderNumber\",\"productCode\",\"quantityOrdered\",\"priceEach\",\"orderLineNumber\"],\"orders_TABLE\":[\"id\",\"ordernumber\",\"orderdate\",\"shippeddate\",\"status\",\"orderarea\",\"city\",\"shipping_delay\",\"payment_type\",\"pincode\"],\"orders1_TABLE\":[\"orderNumber\",\"orderDate\",\"requiredDate\",\"shippedDate\",\"status\",\"comments\",\"customerNumber\"],\"payments_TABLE\":[\"customerNumber\",\"checkNumber\",\"paymentDate\",\"amount\"],\"politics_TABLE\":[\"VOTER\",\"PARTY\",\"PRECINCT\",\"AGE_GROUP\",\"LAST_VOTED\",\"YEARS_REG\",\"BALLOT_STATUS\"],\"product_wise_sale_TABLE\":[\"id\",\"category\",\"item\",\"gender\",\"quantity\",\"total sales\",\"purchase_date\",\"product_code\",\"price_each\",\"cost_price\",\"profit\"],\"productlines_TABLE\":[\"productLine\",\"textDescription\",\"htmlDescription\",\"image\"],\"products_TABLE\":[\"productCode\",\"productName\",\"productLine\",\"productScale\",\"productVendor\",\"productDescription\",\"quantityInStock\",\"buyPrice\",\"MSRP\"],\"retail_TABLE\":[\"id\",\"Year\",\"Category\",\"orderPrice\",\"Month\",\"Region\",\"sorkey\",\"regionid\"],\"sales_summary_TABLE\":[\"Sales Order No\",\"Outlet_Account\",\"Billed By\",\"Invoice No.\",\"Order Billed\",\"Delivery Status\",\"Payment Status\",\"Return Order associated\",\"Sales Channel\",\"Sales Channel Order ID\",\"Payment Ids\",\"Payment Method\",\"Payment Details\",\"Net payable without tax\",\"WaiveOff\",\"total Tax Applied\",\"Net payable with tax\",\"Total Paid Amount\",\"Payment pending Amount\",\"Customer Name\",\"Customer Id\",\"Customer Mobile Number\",\"PAN\",\"GSTIN\",\"Alternate Contact No\",\"Customer E-mail\",\"Customer Address\",\"Pincode\",\"city\",\"State\",\"Country\",\"Order_Date\",\"Invoice_Date\",\"Delivery_Date\"],\"shipping_TABLE\":[\"Contract\",\"Contract_Prepared_purchase\",\"Contract_Prepared_Sales\",\"Contract_type_reference\",\"Supplier\",\"Customer\",\"Item\",\"Qty_MT\",\"size_of_container\",\"Payment_Terms\",\"Mode_of_Payment_customer\",\"Mode_of_Payment_vendor\",\"Advance_from_Customer_amount\",\"Advance_from_Customer_status\",\"Origin_Port_of_Loading\",\"Discharge_Port_Destination\",\"Shipment_Plan\",\"ETD\",\"ETA_BL\",\"BL_Inst\",\"Draft_BL_Received\",\"Shipment_Status\",\"OBL_Received\",\"Shipping_Details_sent_to_Metco_Customer\",\"Paid_to_supplier\",\"Document_Status\",\"Final_Pricing_Status\",\"Status_Remark\",\"TEJI_NOTES\",\"PSIC_CCIC\",\"None\",\"Cut_of_Date\",\"Frt_Fwrdr\",\"Dox_AWB\",\"Booking\",\"Supplier_Payment_Amount\",\"Thro_Metco_Direct\",\"PSIC_Charges_Paid_Unpaid\"],\"summary_instock_TABLE\":[\"SKU\",\"PRODUCT_NAME\",\"HSN/SAC CODE\",\"OUTLET-ACCOUNT\",\"Quantity\"]}}", new TypeReference<Map<String, Object>>(){});

        List<Map<String, Object>> body =new ArrayList<>();
        body.add(b);
        JSONObject bodyJson = new JSONObject();
        for (Map<String, Object> m : body) {

            if (m.containsKey("bodyKey") && m.containsKey("bodyValue")) {
                bodyJson.put(m.get("bodyKey").toString(), m.get("bodyValue").toString());
            } else {
                for (Map.Entry<String, Object> g : m.entrySet()) {
                    bodyJson.put(g.getKey().toString(), g.getValue());
                }

            }

        }

        System.out.println(bodyJson.toString());
        // Generate the key
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

        // Encode the key to Base64 so it can be used as a string
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());

        // Print out the generated key
        System.out.println("Generated Key: " + encodedKey);
    }
}
