-- MySQL dump 10.13  Distrib 5.7.27, for Linux (x86_64)
--
-- Host: localhost    Database: products
-- ------------------------------------------------------
-- Server version	5.7.27-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `orders`
--

DROP TABLE IF EXISTS `orders`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `orders` (
  `order_id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `image` varchar(200) COLLATE utf8_unicode_ci DEFAULT '',
  `price` double NOT NULL,
  `date` int(11) NOT NULL,
  PRIMARY KEY (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `orders`
--

LOCK TABLES `orders` WRITE;
/*!40000 ALTER TABLE `orders` DISABLE KEYS */;
/*!40000 ALTER TABLE `orders` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `products`
--

DROP TABLE IF EXISTS `products`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `products` (
  `product_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(200) COLLATE utf8_unicode_ci DEFAULT '',
  `image` varchar(200) COLLATE utf8_unicode_ci DEFAULT '',
  `text` varchar(4096) COLLATE utf8_unicode_ci DEFAULT '',
  `price` double NOT NULL,
  PRIMARY KEY (`product_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `products`
--

LOCK TABLES `products` WRITE;
/*!40000 ALTER TABLE `products` DISABLE KEYS */;
INSERT INTO `products` VALUES (1,'Moen Glenshire 26-Inch x 22-Inch Frameless Pivoting Bathroom Tilting Mirror','static/images/moen_glenshire.jpg','Featuring a simple yet elegant design, the Moen Glenshire Oval Tilting Mirror gives your bathroom a clean, modern look. With hardware available in chrome and brushed nickel finishes, this frameless beveled mirror pivots, letting you adjust the mirror to your preferred position. All mounting hardware and a template for installation are included. The mirror is backed by Moens Limited Lifetime Warranty.',62.87),(2,'MCS 18x24 Inch Sloped Mirror','static/images/mcs_sloped.jpg','<ul><li>The 3 inch wide frame has a brushed antique silver finish with silver dentil molded inner edge.</li><li>Overall Measurements: 23.5 Inches x 29.5 Inches.</li><li>Reflection Measurements: 18 Inches x 24 Inches.</li><li>Featuring a 1 inch wide bevel.</li><li>4 D-Ring hangers attached for quick and easy installation either vertically or horizontally</li><li>Frame Molding is made from polystyrene material and the mirror is glass</li></ul>',51.84),(3,'Large Simple Rectangular Streamlined 1 Inch Beveled Wall Mirror','static/images/simple.jpg','Our simple large rectangle beveled mirror is perfect for hundreds of styles and locations. Whether you are looking for a bathroom or powder room mirror or something in your home gym or dining or living room, our rectangular beveled plate glass mirror is the perfect solution. Our beveled mirror comes secured to a solid wood backing to add stability and prevent distortion or warping. The wood backing includes our pre-installed slimline 1/4 inch hanging hardware hooks for hanging your mirror in both a horizontal or vertical fashion. The large rectangular portion is surrounded by a simple 1 inch beveled portion to add some flair. The backing is offset an eighth of an inch from the edge to give that floating, clean look while still offering security and support. We stand by our products and your happiness with a 100% money back guarantee.',149.99),(4,'OMIRO Hand Mirror, Black Handheld Mirror with Handle','static/images/handheld.jpg','<ul><li>1X REGULAR MIRROR: Single-sided glass mirror with no magnification, no distortion</li><li>LARGE VIEWING: 6.3 x 5.3 viewing surface</li><li>2-WAY DESIGN: Mirror can be hung up or handheld, its excellent for shaving</li><li>BLACK & STREAM SHAPE: Classic black color & modern rounded rectangle shape</li><li>FREEBIE EYEBROWS RAZOR: A portable eyebrows razor is included in package as a gift for free</li></ul>',6.97),(5,'Crown Mark Espresso Finish Wooden Cheval Bedroom Floor Mirror','static/images/floor.jpg','Espresso finish wood rectangular cheval full length mirror. Mirror tilts for various angles. Easy assembly.',44.99);
/*!40000 ALTER TABLE `products` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reviews`
--

DROP TABLE IF EXISTS `reviews`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reviews` (
  `review_id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `date` int(11) NOT NULL,
  `stars` int(11) NOT NULL,
  `text` varchar(4096) COLLATE utf8_unicode_ci DEFAULT '',
  PRIMARY KEY (`review_id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reviews`
--

LOCK TABLES `reviews` WRITE;
/*!40000 ALTER TABLE `reviews` DISABLE KEYS */;
INSERT INTO `reviews` VALUES (1,7,1,1567313715,5,'Love it. Bought it to go with my Moen Preston collection towel racks and tp holder. Blends nicely. Holds the angle where you put it. Allows for half body view. Makes my small bathroom feel bigger. Easy to install. 15 mins. Oval shape helps conceal that my light is not perfectly centered with the vanity lol. I like the beveled edge and that it comes with proper mounting hardware. Was packaged nicely. No damage upon arrival.'),(2,7,2,1569122070,5,'This is a beautiful mirror. It transformed my bathroom. I still dont understand why the instructions said not to use mirror wire because the hinges that come with the mirror are made to use with wire. The mirror is not too heavy. Since the instructions said not to use mirror wire I bought a 50lb hanging wire (the heaviest available) to make sure that it will last.'),(3,7,2,1568179795,3,'The mirror is beautiful but I had to send it back because it arrived broken. From now on I will order mirrors only through a big box store, pick them up myself, inspect the product before I bring it home.'),(4,14,3,1571832768,5,'I am very happy with this purchase! The mirror is beautiful and was easy to hang.'),(5,11,3,1570176650,4,'Its a mirror and does mirrorly things but what makes it good is the lack of distortion, durability and ease of adding lights behind it.'),(6,5,4,1566331382,5,'My first impression upon reception of the item was that it was a tad smaller than the pictures but when I checked the pictures again realized that it was exactly as advertised. It is very functional and exactly what I was looking for at an awesome price and a FREE gift! I do recommend it.'),(7,17,4,1571898897,5,'I love this little travel mirror! Its big enough to actually see yourself in it, but small enough to carry in a bag. Plus it came with a free gift! A cute little eyebrow trimmer! And it works very well.'),(8,15,4,1573003657,5,'If you or your lady are looking for a hand mirror, this would be a good purchase. Not small enough to be considered a traveling mirror but, it does what a mirror is supposed to do.'),(9,2,4,1573456395,5,'Mirror was packed good for delivery. It arrived in perfect condition. Much bigger than expected but will work out great.'),(10,19,5,1566958250,5,'Ive been looking for a full length mirror for months. Everywhere in stores or online they all were very expensive & not even close to this mirror (in size & quality). This one dont make you look like you are fat or skinny.I look exactly how I am in this mirror & I am very satisfied with this purchase.They shipeed it very carefully (double packed).Easy to assemble.It can enhanced the beauty of any room. I highly recommend this mirror.'),(11,6,5,1571486031,3,'Bought this for my better half because she needed to see her whole outfit. So I found this and decided to give it a shot. The color and size are perfect for my room. Only problem is the amount of damage to the bezel surrounding the mirror and the feet. Its not scratched, just severley dented. It was shipped in very secure packaging. So it either got to the warehouse this way or bad QC at the factory. Just be warned. Hopefully mine is a one-off.');
/*!40000 ALTER TABLE `reviews` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `user_id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
  `password` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
  `cookie` varchar(256) COLLATE utf8_unicode_ci DEFAULT '',
  `credit_card` varchar(100) COLLATE utf8_unicode_ci DEFAULT '',
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'EI1QHwPV0','y1NPwVfBHJD','eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.T2pmMTdnNjlQaDV6cVFIRkpFYm5RbVhtVUpod2VwZHBtaDdwR0VhMmw1dmplM084QVJrNjdSWkw5UXpnOFNkOW40TUx3YjJWRjFFb3JzSUVGUmg5a3RHOUVhQVc1dXlWQ01HMnNGYm1OTzJZU0Q2WDFCM2l6eVRPME43N0JndFo.nc0JC1ITecH+CGkKuq+/Gx258Hb4ysOFG8/YnkEBa0M','VISA:4385-5361-2336-6093'),(2,'Cq7MiS','iKas5CIf','eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.QTd6aEkyMG9remJaNVR4cGdJUTZsZWh4NmxIcVM0NGlSSVI1NFY1dUpMVU5GdXBVejNJcVMwTXlGWHFrbWhTZFFvTXRtMk85cFI5SVEzNVo4b09ia2d0WTQ0aHlHR1p0cG5SV0swSHlBRUJGMFRHT2p6Y2Rxc2J3QVA1ak1BNzc.V7B9A8lC28u+brMF56lRUIaBy4DakJIx/Y4iJwzTxmc','DISCOVER:4409-9611-2321-4504'),(3,'9Dbpbu6A5','F86cLrOO','','MASTERCARD:4344-7226-5915-2612'),(4,'omzubIRQmN','POi6aRl','','MASTERCARD:4318-4306-5524-9351'),(5,'iaBRXvEPZCWS','bsrvjz0','eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.Z1dSbEl0VVR1UnVMZ21pZG1LemtSVU9IcVdsT3ZJUHc2QVQwWGJQeUs0QmJsMFdKZzR1ZWdqSFBqeGRnRTJmam16c3g5aW9abzJzd2RyWWM4QVBWdldUM1oybmFwcUhnR0J4SEJTVTRVVnhGN0FaYXZjVVlSbWdJTkYxR2NRS3I.T4iGKKwK56VfMVjJVK6nHRZ0/E/fid1AGvRp1gXHmy8','MASTERCARD:4920-7360-2274-3556'),(6,'niZljKeT','lkDccgPB','eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.aUo5V0tKVkxXREJxdXZsaFB2elFURFhxSGJjZTJmWk1Za25wVDIyWXV4MFB4RVR4bVdRdzZIazYyNE04WmllQmRkVkR1YnlLMHR4Y0E5UGdlVldRNlY0ckdtRUlzaFlyandPYVo5TVJpZ1dlS1hGQk5iWGo5RXlGV2g1T3J0b1A.TIW7qfLNdbmZxxH96WwbPOPPy60QNLMDjPgfxZ8TceM','AMERICAN EXPRESS:4711-5717-1216-4057'),(7,'1MIKAuE8B','buSFvu','eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.NU92enhONzZkcTVEbEpESjl2ZGJZWlBoWVFwRjNSTXJmOU16R1FQUlhNNlpROTM1S3dNUUVTbUJhMGRsUHlkVWtlQ0VhZXNvUDQxQjh5TWRhY2Z1MVpId3lCVkxGMHgyWkxaaVo3T0Z2a205Yk5YeER5WnRnb0dET29tdUpRVDk.NkRv5+A2OLvumiyv2oWYLub/dJJ4JDuc+lQiLA3PlT4','DISCOVER:4370-6120-5198-2327'),(8,'THLRDz2rL0','8D7tln','','MASTERCARD:4514-1834-1816-1244'),(9,'WeMJnbzl','cQLpYB','','AMERICAN EXPRESS:4950-2280-3106-7902'),(10,'h6lrU2sMRpUx','jwSswc','','VISA:4585-5021-6761-6824'),(11,'BXCBxE2','iLNCsSQw','','VISA:4841-8050-5972-7799'),(12,'t2SRJ1q','8HHyCD0Pf','eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.SmVaQU9HdGdTUWRtUFJaZzRJVU44Y3FBNjY5cnhWUWF6WFA0SzJsR1FlUU1aUlNmblhRMkFrVjNrWnV5dTdRNTRxSm1JbU5CcVROTzFzRVBUalZlNGMzQjFOc2NPTUJ3cGtRQUt1b1hsNWdvTFpZU2J4Z0VLcnNTYWtKM1JBUmo.G7AsoFUkvMsxw8BwKgY3q/raBvgxi90E3X+2ZAQahXU','VISA:4645-5801-9508-9520'),(13,'GSqbRRByHYd','kV3Y3iOF','','DISCOVER:4349-5050-4280-2491'),(14,'TpeSTrFENSy','bDsda1TikxWf','','AMERICAN EXPRESS:4188-1341-8222-8499'),(15,'fY6P9vYa','761ezx','','MASTERCARD:4188-2800-8262-9678'),(16,'8vLu32hc8','DF9DbNY7VC','','AMERICAN EXPRESS:4906-3582-8906-6001'),(17,'froJe0bbfk','1Pjj4wpnQ03','','VISA:4727-4166-3676-9050'),(18,'mQFVpWJp2XW','yaxv1NR','','DISCOVER:4155-7677-9353-5056'),(19,'oLlgKh61w','oEXXqrv3eR','','DISCOVER:4103-3954-4431-4728'),(20,'ZDOPmFW5qt','2rLDmLT','','VISA:4268-1320-4313-7445'),(21,'MGjTyFfFDP6I','kOo264','','DISCOVER:4227-2540-4478-1221'),(22,'nD6Hc2mBiIQ','C48OPKGP1','','MASTERCARD:4354-5761-7662-5796'),(23,'KSdAdKjq','G6I90cuIRY5j','eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.VWdncmVydUJJTzkwOXVkTXhVSGZTZm9DdmVEeUJzSDlZTTJqbTdJSVhYaldka3FPQjE2Yk9RZkkyeWZ5WHVuWFNIZmtLalZUSVpRZjU4d1JGV0VQck0zZGVxZGhrd2Fua0dDQmJxbmlaMjlqSUpLTjRSTHpZWVYzeWU3cHkyRWI.NG3HqHS43DWp6OogMKtkZIMX7uhEgqkjN8uDj2HpIsE','DISCOVER:4976-6118-7944-5117');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-11-14  7:35:52
